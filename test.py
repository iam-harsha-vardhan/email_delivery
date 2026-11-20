# app.py
import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
import datetime
import re
import ipaddress
from collections import Counter
import pandas as pd
import pytz
import base64
import concurrent.futures
from typing import List

# ---------- Basic page ----------
st.set_page_config(page_title="Dynamic Multi-Account Inbox Comparator", layout="wide")
st.title("📧 Dynamic Multi-Account Inbox Comparator")

# ---------- Configurable defaults (no UI knobs shown) ----------
UID_SCAN_LIMIT = 2000  # how many recent UIDs to scan when using time windows
CHUNK_SIZE = 200       # how many UIDs to fetch per IMAP UID FETCH call

# ---------- Session state defaults ----------
if "creds_df" not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{"Email": "", "Password": ""}])
if "mailbox_data" not in st.session_state:
    st.session_state.mailbox_data = {}  # {email: {"last_uid":..., "df": DataFrame, "uid_date_cache": {uid: datetime}}}

# ---------- Helper constructors ----------
def get_empty_mailbox_structure():
    return {
        "last_uid": None,
        "df": pd.DataFrame(columns=[
            "UID", "Domain", "Subject", "From", "Message-ID", "Date", "Date_dt",
            "Blast/Sub ID", "Type", "IP", "SPF", "DKIM", "DMARC", "is_new"
        ]),
        "uid_date_cache": {}
    }

def apply_default_index(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.index = range(1, len(df) + 1)
    df.index.name = "#"
    return df

# ---------- Utilities ----------
def decode_mime_words(s):
    if not s:
        return ""
    decoded = ""
    for word, enc in decode_header(s):
        if isinstance(word, bytes):
            try:
                decoded += word.decode(enc or "utf-8", errors="ignore")
            except Exception:
                decoded += word.decode("utf-8", errors="ignore")
        else:
            decoded += word
    return decoded.strip()

def extract_domain_from_address(address):
    if not address:
        return "-"
    m = re.search(r'@([\w\.-]+)', address)
    return m.group(1).lower() if m else "-"

def extract_auth_results_from_headers(msg):
    auth = msg.get("Authentication-Results", "") or " ".join(f"{h}: {v}" for h, v in msg.items())
    spf = dkim = dmarc = "neutral"
    m_spf = re.search(r'spf=(\w+)', auth, re.I)
    m_dkim = re.search(r'dkim=(\w+)', auth, re.I)
    m_dmarc = re.search(r'dmarc=(\w+)', auth, re.I)
    if m_spf:
        spf = m_spf.group(1).lower()
    if m_dkim:
        dkim = m_dkim.group(1).lower()
    if m_dmarc:
        dmarc = m_dmarc.group(1).lower()
    return spf, dkim, dmarc

def validate_ip(candidate):
    if not candidate:
        return None
    cleaned = candidate.strip().strip("[]();,<>")
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return None

def extract_sending_ip(msg):
    # 1. Priority: Received-SPF client-ip=... (present on Gmail even on fail/softfail/neutral)
    for spf_hdr in msg.get_all("Received-SPF", []) or []:
        m = re.search(r'client-ip=([^\s;]+)', str(spf_hdr), re.I)
        if m:
            ip = validate_ip(m.group(1))
            if ip:
                return ip

    # 2. Priority: External hop Received: from ... [IP] by mx.google.com
    received_headers = msg.get_all("Received", []) or []
    for rec in received_headers:
        rec_str = str(rec)
        if re.search(r'by\s+mx\.google\.com', rec_str, re.I):
            for bracket_val in re.findall(r'\[([^\]]+)\]', rec_str):
                ip = validate_ip(bracket_val)
                if ip:
                    return ip

    # 3. Priority: Authentication-Results / ARC-Authentication-Results designates <IP>
    for hdr_name in ("Authentication-Results", "ARC-Authentication-Results"):
        for auth_hdr in msg.get_all(hdr_name, []) or []:
            auth_str = str(auth_hdr)
            for pattern in (r'client-ip=([^\s;)]+)', r'designates\s+([^\s;)]+)'):
                m = re.search(pattern, auth_str, re.I)
                if m:
                    ip = validate_ip(m.group(1))
                    if ip:
                        return ip

    # 4. Fallback: First public IP in a Received: from ... [IP] header
    for rec in received_headers:
        rec_str = str(rec)
        if re.search(r'\bfrom\b', rec_str, re.I):
            for bracket_val in re.findall(r'\[([^\]]+)\]', rec_str):
                ip = validate_ip(bracket_val)
                if ip:
                    ip_obj = ipaddress.ip_address(ip)
                    if not (ip_obj.is_private or ip_obj.is_loopback):
                        return ip

    return "-"

# Sub-ID extraction
ID_RE = re.compile(
    r'\b(GRM-[A-Za-z0-9.\-]+|GMFP-[A-Za-z0-9.\-]+|GTC-[A-Za-z0-9.\-]+|GRTC-[A-Za-z0-9.\-]+)\b',
    re.I
)

def map_id_to_type(sub_id):
    if not sub_id:
        return "-"
    lid = sub_id.lower()
    if lid.startswith("grm"):
        return "FPR"
    if lid.startswith("gmfp"):
        return "FP"
    if lid.startswith("gtc"):
        return "FPTC"
    if lid.startswith("grtc"):
        return "FPRTC"
    return "-"

BLAST_ID_RE = re.compile(r'^[0-9][A-Za-z0-9]{11}$')

def is_valid_blast_id(value):
    return bool(value and BLAST_ID_RE.fullmatch(value.strip()))

def get_message_id_local_part(message_id):
    if not message_id:
        return ""
    value = message_id.strip().strip("<>")
    return value.rsplit("@", 1)[0] if "@" in value else value

def split_message_id_candidates(local_part):
    if not local_part:
        return []
    parts = [local_part]
    parts.extend(re.split(r'[_:|;,<>\s]+', local_part))
    return list(dict.fromkeys(p.strip() for p in parts if p and p.strip()))

def find_blast_ids_in_text(text):
    if not text:
        return []
    found = []
    for value in re.findall(r'(?<![A-Za-z0-9])[0-9][A-Za-z0-9]{11}(?![A-Za-z0-9])', text):
        value = value.lower()
        if value not in found:
            found.append(value)
    clean = text.strip()
    if is_valid_blast_id(clean) and clean.lower() not in found:
        found.append(clean.lower())
    return found

def try_base64_variants(s):
    if not s or len(s) < 4:
        return None
    s = s.strip()
    if s.startswith("<") and s.endswith(">"):
        s = s[1:-1]
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        for pad in range(0, 4):
            try:
                cand = s + ("=" * pad)
                decoded = decoder(cand)
                try:
                    text = decoded.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if text and text.strip():
                    return text
            except Exception:
                continue
    return None

def extract_blast_id(message_id):
    if not message_id:
        return "-"
    found = []

    def add(value):
        if not value:
            return
        value = value.strip()
        if is_valid_blast_id(value):
            value = value.lower()
            if value not in found:
                found.append(value)
        for blast in find_blast_ids_in_text(value):
            if blast not in found:
                found.append(blast)

    local_part = get_message_id_local_part(message_id)
    if not local_part:
        return "-"

    add(local_part)

    for candidate in split_message_id_candidates(local_part):
        add(candidate)
        decoded = try_base64_variants(candidate)
        if decoded:
            add(decoded)
            for nested in re.split(r'[_:|;,<>\s]+', decoded):
                if not nested:
                    continue
                add(nested)
                nested_decoded = try_base64_variants(nested)
                if nested_decoded:
                    add(nested_decoded)

    return ", ".join(found) if found else "-"

def find_subid_in_text(txt):
    if not txt:
        return None
    m = ID_RE.search(txt)
    return m.group(1) if m else None

def format_date_to_ist_string(raw_date):
    if not raw_date:
        return "-", None
    try:
        dt = parsedate_to_datetime(raw_date)
    except Exception:
        return raw_date, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    ist = pytz.timezone("Asia/Kolkata")
    dt_ist = dt.astimezone(ist)
    dt_ist_naive = dt_ist.replace(tzinfo=None)
    formatted = dt_ist.strftime("%d-%b-%Y %I:%M %p")
    return formatted, dt_ist_naive

def extract_subid_from_msg(msg):
    msg_id_raw = decode_mime_words(
        msg.get("Message-ID", "") or msg.get("Message-Id", "") or ""
    )

    prefixes = ("GRM-", "GMFP-", "GTC-", "GRTC-")

    if msg_id_raw:
        tokens = re.split(r'[_:|;,<>\s@]+', msg_id_raw.strip("<>"))
        for token in tokens:
            if not token or len(token) < 6:
                continue
            if token.upper().startswith(prefixes):
                return token.strip(), map_id_to_type(token.strip())
            decoded = try_base64_variants(token)
            if decoded:
                decoded = decoded.strip()
                if decoded.upper().startswith(prefixes):
                    return decoded, map_id_to_type(decoded)
                m = find_subid_in_text(decoded)
                if m:
                    return m, map_id_to_type(m)

    headers_str = " ".join(f"{h}:{v}" for h, v in msg.items())
    m = find_subid_in_text(headers_str)
    if m:
        return m, map_id_to_type(m)

    return None, "-"

def parse_message_header_bytes(uid_str, hdr_bytes):
    msg = email.message_from_bytes(hdr_bytes)
    subject = decode_mime_words(msg.get("Subject", "No Subject"))
    from_h = decode_mime_words(msg.get("From", "-"))
    domain = extract_domain_from_address(from_h)
    spf, dkim, dmarc = extract_auth_results_from_headers(msg)
    sub_id, id_type = extract_subid_from_msg(msg)
    message_id = decode_mime_words(msg.get("Message-ID", ""))
    blast_id = extract_blast_id(message_id)
    sending_ip = extract_sending_ip(msg)
    raw_date = msg.get("Date", "")
    formatted, dt = format_date_to_ist_string(raw_date)
    return {
        "UID": uid_str,
        "Domain": domain,
        "Subject": subject,
        "From": from_h,
        "Message-ID": message_id,
        "Date": formatted,
        "Date_dt": dt,
        "Blast/Sub ID": (sub_id if sub_id else (blast_id if blast_id != "-" else "-")),
        "Type": id_type,
        "IP": sending_ip,
        "SPF": spf,
        "DKIM": dkim,
        "DMARC": dmarc
    }

def parse_fetch_parts_for_uid_and_date(fetch_response_parts) -> List[tuple]:
    results = []
    for part in fetch_response_parts:
        if not isinstance(part, tuple):
            continue
        header_bytes, body_bytes = part[0], part[1]
        try:
            meta = header_bytes.decode("utf-8", errors="ignore")
        except Exception:
            try:
                meta = str(header_bytes)
            except Exception:
                meta = ""
        uid_match = re.search(r'UID\s+(\d+)', meta)
        uid_str = uid_match.group(1) if uid_match else None
        raw_date = ""
        if body_bytes:
            try:
                body_text = body_bytes.decode("utf-8", errors="ignore")
            except Exception:
                body_text = str(body_bytes)
            m = re.search(r'Date:\s*(.+)', body_text, flags=re.I)
            if m:
                raw_date = m.group(1).strip()
        if uid_str:
            results.append((uid_str, raw_date))
    return results

# ---------- Core fetch function (Optimized for O(1) Incremental & Limits) ----------
def fetch_inbox_emails_single(
    email_addr, password, last_uid=None, fetch_type="incremental",
    fetch_n=None, fetch_unit="emails", uid_scan_limit=UID_SCAN_LIMIT, chunk_size=CHUNK_SIZE
):
    results = []
    new_last_uid = last_uid
    try:
        email_addr = email_addr.strip()
        password = password.strip()
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_addr, password)
        imap.select("inbox")

        uids = []

        # O(1) Fetch utilizing UID limits
        if fetch_type == "incremental" and last_uid is not None:
            next_uid = int(last_uid) + 1
            status, data = imap.uid("search", None, f"UID {next_uid}:*")
            if status == "OK" and data and data[0]:
                raw_uids = data[0].split()
                uids = [u for u in raw_uids if int(u.decode()) >= next_uid]

        elif fetch_unit == "emails" and fetch_n:
            status, data = imap.uid("search", None, "ALL")
            if status == "OK" and data and data[0]:
                all_uids = data[0].split()
                uids = all_uids[-int(fetch_n):]

        elif fetch_unit in ("hours", "minutes") and fetch_n:
            ist = pytz.timezone("Asia/Kolkata")
            now_ist = datetime.datetime.now(ist).replace(tzinfo=None)
            if fetch_unit == "hours":
                cutoff = now_ist - datetime.timedelta(hours=int(fetch_n))
            else:
                cutoff = now_ist - datetime.timedelta(minutes=int(fetch_n))

            status, data = imap.uid("search", None, "ALL")
            if status == "OK" and data and data[0]:
                all_uids = data[0].split()
                uids_to_check = all_uids[-uid_scan_limit:] if len(all_uids) > uid_scan_limit else all_uids
                matched_uids = []
                for i in range(0, len(uids_to_check), chunk_size):
                    chunk = uids_to_check[i:i + chunk_size]
                    uid_seq = b",".join(chunk)
                    try:
                        res, fdata = imap.uid("fetch", uid_seq, "(BODY.PEEK[HEADER.FIELDS (DATE)])")
                    except Exception:
                        for u in chunk:
                            try:
                                uid_str = u.decode()
                                r, md = imap.uid("fetch", uid_str, "(BODY.PEEK[HEADER.FIELDS (DATE)])")
                                if r != "OK" or not md:
                                    continue
                                parsed = parse_fetch_parts_for_uid_and_date(md)
                                for (uid_s, raw_date) in parsed:
                                    if not raw_date:
                                        continue
                                    _, dt = format_date_to_ist_string(raw_date)
                                    if dt and dt >= cutoff:
                                        matched_uids.append(uid_s.encode())
                            except Exception:
                                continue
                        continue

                    parsed = parse_fetch_parts_for_uid_and_date(fdata)
                    for uid_str, raw_date in parsed:
                        if not raw_date:
                            continue
                        _, dt = format_date_to_ist_string(raw_date)
                        if dt and dt >= cutoff:
                            matched_uids.append(uid_str.encode())
                uids = matched_uids
        else:
            ist = pytz.timezone("Asia/Kolkata")
            today_ist = datetime.datetime.now(ist).strftime("%d-%b-%Y")
            status, data = imap.uid("search", None, f'(SINCE "{today_ist}")')
            if status == "OK" and data and data[0]:
                uids = data[0].split()

        if not uids:
            imap.logout()
            return pd.DataFrame(results), new_last_uid

        # Batch-fetch matched uids
        for i in range(0, len(uids), chunk_size):
            chunk = uids[i:i + chunk_size]
            uid_seq = b",".join(chunk)
            try:
                res, fdata = imap.uid("fetch", uid_seq, "(BODY.PEEK[HEADER])")
            except Exception:
                for u in chunk:
                    try:
                        uid_s = u.decode()
                        r2, md2 = imap.uid("fetch", uid_s, "(BODY.PEEK[HEADER])")
                        if r2 != "OK" or not md2 or not isinstance(md2[0], tuple):
                            continue
                        results.append(parse_message_header_bytes(uid_s, md2[0][1]))
                        if new_last_uid is None or (uid_s.isdigit() and int(uid_s) > int(new_last_uid)):
                            new_last_uid = uid_s
                    except Exception:
                        continue
                continue

            for part in fdata:
                if not isinstance(part, tuple):
                    continue
                uid_found = None
                try:
                    meta = part[0].decode("utf-8", errors="ignore")
                    m = re.search(r'UID\s+(\d+)', meta)
                    if m:
                        uid_found = m.group(1)
                except Exception:
                    uid_found = None
                if uid_found is None:
                    continue
                try:
                    results.append(parse_message_header_bytes(uid_found, part[1]))
                except Exception:
                    continue
                if new_last_uid is None or (uid_found.isdigit() and int(uid_found) > int(new_last_uid)):
                    new_last_uid = uid_found

        imap.logout()

    except Exception as e:
        raise Exception(f"IMAP Error: {e}")

    df = pd.DataFrame(results)
    return df, new_last_uid

# ---------- Styling ----------
def highlight_new_rows(row):
    return ["background-color: #90EE90"] * len(row) if row.get("is_new", False) else [""] * len(row)

def highlight_presence_row(row):
    try:
        if str(row.get("Auth", "")).lower() != "pass":
            style = "background-color: rgba(255, 0, 0, 0.15)"
            return [style] * len(row)
    except Exception:
        pass
    return highlight_new_rows(row)

# ---------- UI: accounts ----------
st.markdown("### 📋 Account Credentials")
st.info("Add accounts (App Password recommended for Gmail).")

column_config = {
    "Email": st.column_config.TextColumn("Email", width="medium", required=True),
    "Password": st.column_config.TextColumn("App Password", width="medium", required=True),
}
edited_df = st.data_editor(
    st.session_state.creds_df,
    num_rows="dynamic",
    column_config=column_config,
    key="editor",
    use_container_width=True,
    hide_index=False
)
st.session_state.creds_df = edited_df

# ---------- Thread-Safe Fetch Worker ----------
def fetch_worker(email_addr, pwd, last_uid, fetch_type, fetch_n, fetch_unit):
    try:
        df, n_uid = fetch_inbox_emails_single(
            email_addr, pwd, last_uid=last_uid,
            fetch_type=fetch_type, fetch_n=fetch_n, fetch_unit=fetch_unit,
            uid_scan_limit=UID_SCAN_LIMIT, chunk_size=CHUNK_SIZE
        )
        return email_addr, df, n_uid, None
    except Exception as e:
        return email_addr, pd.DataFrame(), last_uid, str(e)

# ---------- Exposed process_fetch (Parallelized) ----------
def process_fetch(fetch_type, fetch_n=None, fetch_unit="emails"):
    any_run = False

    # 1. Strip 'is_new' status globally before kicking off fresh fetch
    for email_addr, mailbox in st.session_state.mailbox_data.items():
        if "is_new" in mailbox["df"].columns:
            mailbox["df"]["is_new"] = False

    futures = []
    errors = []

    # 2. Spawn concurrent fetch threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for _, r in st.session_state.creds_df.iterrows():
            email_addr = str(r.get("Email", "") or "").strip()
            pwd = str(r.get("Password", "") or "").strip()
            if not email_addr or not pwd:
                continue

            if email_addr not in st.session_state.mailbox_data:
                st.session_state.mailbox_data[email_addr] = get_empty_mailbox_structure()

            mailbox = st.session_state.mailbox_data[email_addr]
            futures.append(executor.submit(
                fetch_worker, email_addr, pwd, mailbox.get("last_uid"), fetch_type, fetch_n, fetch_unit
            ))

    # 3. Process completed threads and merge DataFrames
    for future in concurrent.futures.as_completed(futures):
        email_addr, df_new, new_uid, err = future.result()
        if err:
            errors.append(f"{email_addr}: {err}")
        elif df_new is not None and not df_new.empty:
            any_run = True
            df_new["is_new"] = True
            mailbox = st.session_state.mailbox_data[email_addr]
            mailbox["df"] = pd.concat([mailbox["df"], df_new], ignore_index=True).drop_duplicates(
                subset=["UID"], keep="last"
            )
            mailbox["last_uid"] = new_uid

    if errors:
        for error in errors:
            st.error(error)

    return any_run

# ---------- One-line control bar ----------
st.markdown("---")
col_f1, col_f2, col_f3, col_f4, col_f5 = st.columns([1.2, 1.2, 2.2, 1.5, 1.0])

with col_f1:
    if st.button("🔄 Fetch New (incremental)"):
        ok = process_fetch("incremental")
        st.success("Fetched incremental emails." if ok else "No new emails found.")

with col_f2:
    fetch_n = st.number_input("N", min_value=1, value=100, step=1, label_visibility="collapsed", key="compact_fetch_n2")
    fetch_unit = st.selectbox("Unit", ["emails", "hours", "minutes"], index=2, label_visibility="collapsed", key="compact_unit2")
    if st.button("📥 Fetch Last N"):
        ok = process_fetch("last_n", fetch_n=fetch_n, fetch_unit=fetch_unit)
        st.success(f"Fetched last {fetch_n} {fetch_unit}." if ok else "No new emails found.")

with col_f3:
    non_empty = [r for _, r in st.session_state.creds_df.iterrows() if str(r.get("Email", "") or "").strip()]
    avail = max(1, len(non_empty))
    default_n = 4 if avail >= 4 else avail
    required_accounts_count = st.number_input(
        "Require Sub-ID/Blast-ID presence in at least N accounts",
        min_value=1, max_value=avail, value=default_n, step=1, key="req_n"
    )

with col_f4:
    ip_analysis_mode = st.toggle(
        "🔍 IP-Level Analysis",
        value=False,
        key="ip_analysis_mode",
        help="OFF: Clean ✅ / ❌ view. ON: Show delivered IP per account, IP counts per mail, and Domain/IP diagnostics."
    )

with col_f5:
    if st.button("🗑️ Clear All"):
        st.session_state.mailbox_data = {}
        st.success("Cleared all fetched emails.")
        st.rerun()

st.markdown("---")

# ---------- Counts ----------
st.markdown("### 📊 Email Counts per Account")
if not st.session_state.mailbox_data:
    st.write("No data fetched yet.")
else:
    active_emails = list(st.session_state.mailbox_data.keys())
    if active_emails:
        cols = st.columns(len(active_emails))
        for i, em in enumerate(active_emails):
            mailbox = st.session_state.mailbox_data[em]
            total = len(mailbox["df"])
            newc = int(mailbox["df"]["is_new"].sum()) if "is_new" in mailbox["df"].columns else 0
            with cols[i]:
                st.metric(label=em.split("@")[0], value=total, delta=f"{newc} New" if newc > 0 else None)

st.markdown("---")

# ---------- Build Blast/Sub ID grouped map ----------
valid_emails = [
    str(r["Email"]).strip()
    for _, r in st.session_state.creds_df.iterrows()
    if str(r.get("Email", "") or "").strip() in st.session_state.mailbox_data
]
# Preserve unique order of valid accounts
valid_emails = list(dict.fromkeys(valid_emails))

mail_groups = {}
all_flat_rows = []

for email_addr in valid_emails:
    df_acc = st.session_state.mailbox_data[email_addr]["df"]
    if df_acc.empty:
        continue
    for _, row in df_acc.iterrows():
        sid = str(row.get("Blast/Sub ID", "-") or "-").strip()
        domain = row.get("Domain", "-") or "-"
        from_val = row.get("From", "-") or "-"
        subject = row.get("Subject", "-") or "-"
        ip_val = str(row.get("IP", "-") or "-").strip()
        spf = str(row.get("SPF", "neutral") or "neutral").lower()
        dkim = str(row.get("DKIM", "neutral") or "neutral").lower()
        dmarc = str(row.get("DMARC", "neutral") or "neutral").lower()
        auth_ok = (spf == "pass" and dkim == "pass" and dmarc == "pass")

        # Treat identical Blast/Sub ID as the exact same mail sent across accounts
        if sid != "-":
            group_key = ("id", sid)
            has_id = True
        else:
            group_key = ("fallback", domain, from_val, subject)
            has_id = False

        grp = mail_groups.setdefault(group_key, {
            "has_id": has_id,
            "identifier": sid,
            "rows": []
        })
        entry = {
            "account": email_addr,
            "Domain": domain,
            "From": from_val,
            "Subject": subject,
            "UID": row.get("UID"),
            "Message-ID": row.get("Message-ID"),
            "Date": row.get("Date") or "-",
            "Date_dt": row.get("Date_dt"),
            "Blast/Sub ID": sid,
            "IP": ip_val,
            "SPF": spf,
            "DKIM": dkim,
            "DMARC": dmarc,
            "auth_ok": auth_ok,
            "is_new": bool(row.get("is_new", False)),
            "group_key": group_key
        }
        grp["rows"].append(entry)
        all_flat_rows.append(entry)


def get_identifier_column_name(df):
    if df.empty:
        return "Blast/Sub ID"
    values = df["Blast/Sub ID"].dropna().astype(str).str.strip()
    values = values[values != "-"]
    if values.empty:
        return "Blast/Sub ID"
    subid_mask = values.str.match(r'^(GRM|GMFP|GTC|GRTC)-', case=False, na=False)
    subid_count = int(subid_mask.sum())
    blast_count = int((~subid_mask).sum())
    if subid_count > 0 and blast_count == 0:
        return "Sub ID"
    if blast_count > 0 and subid_count == 0:
        return "Blast ID"
    return "Blast/Sub ID"


identifier_frames = []
for em in valid_emails:
    df_tmp = st.session_state.mailbox_data[em]["df"]
    if not df_tmp.empty and "Blast/Sub ID" in df_tmp.columns:
        identifier_frames.append(df_tmp["Blast/Sub ID"])

if identifier_frames:
    identifier_series = pd.concat(identifier_frames, ignore_index=True)
    identifier_column_name = get_identifier_column_name(pd.DataFrame({"Blast/Sub ID": identifier_series}))
else:
    identifier_column_name = "Blast/Sub ID"


def summarize_group(grp, active_accounts, ip_mode: bool):
    rows_list = grp["rows"]
    # Pick representative Domain / From / Subject from the newest message in the group
    latest_entry = max(
        rows_list,
        key=lambda r: (r["Date_dt"] is not None, r["Date_dt"] or datetime.datetime.min)
    )
    latest_dt = latest_entry["Date_dt"]
    latest_str = latest_entry["Date"]
    domain = latest_entry["Domain"]
    from_val = latest_entry["From"]
    subject = latest_entry["Subject"]

    accounts_present = {r["account"] for r in rows_list}
    all_auth_pass = all(r["auth_ok"] for r in rows_list)
    any_new = any(r["is_new"] for r in rows_list)

    # IP counts across all deliveries of this mail
    valid_ips = [r["IP"] for r in rows_list if r["IP"] and r["IP"] != "-"]
    ip_counter = Counter(valid_ips)
    unique_ip_count = len(ip_counter)
    ip_breakdown = ", ".join(f"{ip} ({cnt})" for ip, cnt in ip_counter.most_common()) if ip_counter else "-"
    delivered_str = f"{len(accounts_present)}/{len(active_accounts)}"

    # Per-account display cell
    per_acc_cells = {}
    for em in active_accounts:
        acc_label = em.split("@")[0]
        acc_rows = [r for r in rows_list if r["account"] == em]
        if not acc_rows:
            per_acc_cells[acc_label] = "❌"
        elif not ip_mode:
            per_acc_cells[acc_label] = "✅"
        else:
            acc_ips = list(dict.fromkeys(r["IP"] for r in acc_rows if r["IP"] and r["IP"] != "-"))
            per_acc_cells[acc_label] = ", ".join(acc_ips) if acc_ips else "✅ (No IP)"

    return {
        "Domain": domain,
        "From": from_val,
        "Subject": subject,
        "Identifier": grp["identifier"],
        "Time (IST)": latest_str,
        "Date_dt": latest_dt,
        "Delivered": delivered_str,
        "Unique IPs": unique_ip_count,
        "IP Breakdown": ip_breakdown,
        "accounts_present_count": len(accounts_present),
        "all_auth_pass": all_auth_pass,
        "Auth": "Pass" if all_auth_pass else "Fail",
        "is_new": any_new,
        "per_acc_cells": per_acc_cells
    }


per_acc_cols = [e.split("@")[0] for e in valid_emails]

# ---------- TOP: Identifier Consensus table ----------
mode_badge = "IP-Level View" if ip_analysis_mode else "Standard View"
st.subheader(f"🔎 Identifier Consensus (≥ {required_accounts_count} accounts) — {mode_badge}")

consensus_items = []
for gkey, grp in mail_groups.items():
    if not grp["has_id"]:
        continue
    summary = summarize_group(grp, valid_emails, ip_analysis_mode)
    if summary["accounts_present_count"] < required_accounts_count:
        continue
    if not summary["all_auth_pass"]:
        continue

    row = {
        "Domain": summary["Domain"],
        "From": summary["From"],
        "Subject": summary["Subject"],
        identifier_column_name: summary["Identifier"],
        "Time (IST)": summary["Time (IST)"],
        "Delivered": summary["Delivered"],
        "Unique IPs": summary["Unique IPs"],
        "IP Breakdown": summary["IP Breakdown"],
        "is_new": summary["is_new"]
    }
    row.update(summary["per_acc_cells"])
    consensus_items.append((summary["Date_dt"], row))

consensus_sorted = [
    r for _, r in sorted(
        consensus_items,
        key=lambda x: (x[0] is not None, x[0] or datetime.datetime.min),
        reverse=True
    )
]

if consensus_sorted:
    consensus_df = pd.DataFrame(consensus_sorted)
    if ip_analysis_mode:
        display_cols = (
            ["Domain", "From", "Subject", identifier_column_name, "Time (IST)", "Delivered", "Unique IPs", "IP Breakdown"]
            + per_acc_cols + ["is_new"]
        )
    else:
        display_cols = (
            ["Domain", "From", "Subject", identifier_column_name, "Time (IST)"]
            + per_acc_cols + ["is_new"]
        )
    consensus_df = apply_default_index(consensus_df.reindex(columns=display_cols, fill_value="-"))
    st.dataframe(
        consensus_df.style.apply(highlight_new_rows, axis=1),
        hide_index=False,
        column_config={"is_new": None},
        use_container_width=True
    )
else:
    st.info(f"No identifiers that meet the threshold of {required_accounts_count} accounts with all auths passing.")

st.markdown("---")

# ---------- MIDDLE: Email Presence table (Grouped by Blast/Sub ID) ----------
st.subheader(f"📋 Email Presence Table (Newest on Top) — {mode_badge}")

presence_items = []
for gkey, grp in mail_groups.items():
    summary = summarize_group(grp, valid_emails, ip_analysis_mode)
    row = {
        "Domain": summary["Domain"],
        "From": summary["From"],
        "Subject": summary["Subject"],
        identifier_column_name: summary["Identifier"],
        "Time (IST)": summary["Time (IST)"],
        "Delivered": summary["Delivered"],
        "Unique IPs": summary["Unique IPs"],
        "IP Breakdown": summary["IP Breakdown"],
        "Auth": summary["Auth"],
        "is_new": summary["is_new"]
    }
    row.update(summary["per_acc_cells"])
    presence_items.append((summary["Date_dt"], row))

presence_sorted = [
    r for _, r in sorted(
        presence_items,
        key=lambda x: (x[0] is not None, x[0] or datetime.datetime.min),
        reverse=True
    )
]

if presence_sorted:
    presence_df = pd.DataFrame(presence_sorted)
    if ip_analysis_mode:
        display_cols = (
            ["Domain", "From", "Subject", identifier_column_name, "Time (IST)", "Delivered", "Unique IPs", "IP Breakdown"]
            + per_acc_cols + ["Auth", "is_new"]
        )
    else:
        display_cols
