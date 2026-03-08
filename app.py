# app.py
import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
import datetime
import re
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
            "UID", "Domain", "Subject", "From", "Message-ID", "Date", "Date_dt", "Sub ID", "Type", "SPF", "DKIM", "DMARC", "is_new"
        ]),
        "uid_date_cache": {} 
    }

# ---------- Utilities ----------
def decode_mime_words(s):
    if not s: return ""
    decoded = ''
    for word, enc in decode_header(s):
        if isinstance(word, bytes):
            try:
                decoded += word.decode(enc or 'utf-8', errors='ignore')
            except Exception:
                decoded += word.decode('utf-8', errors='ignore')
        else:
            decoded += word
    return decoded.strip()

def extract_domain_from_address(address):
    if not address: return "-"
    m = re.search(r'@([\w\.-]+)', address)
    return m.group(1).lower() if m else "-"

def extract_auth_results_from_headers(msg):
    auth = msg.get("Authentication-Results", "") or " ".join(f"{h}: {v}" for h, v in msg.items())
    spf = dkim = dmarc = 'neutral'
    m_spf = re.search(r'spf=(\w+)', auth, re.I)
    m_dkim = re.search(r'dkim=(\w+)', auth, re.I)
    m_dmarc = re.search(r'dmarc=(\w+)', auth, re.I)
    if m_spf: spf = m_spf.group(1).lower()
    if m_dkim: dkim = m_dkim.group(1).lower()
    if m_dmarc: dmarc = m_dmarc.group(1).lower()
    return spf, dkim, dmarc

# Sub-ID extraction
ID_RE = re.compile(r'\b(GRM-[A-Za-z0-9\-]+|GMFP-[A-Za-z0-9\-]+|GTC-[A-Za-z0-9\-]+|GRTC-[A-Za-z0-9\-]+)\b', re.I)
def map_id_to_type(sub_id):
    if not sub_id: return "-"
    lid = sub_id.lower()
    if lid.startswith('grm'): return 'FPR'
    if lid.startswith('gmfp'): return 'FP'
    if lid.startswith('gtc'): return 'FPTC'
    if lid.startswith('grtc'): return 'FPRTC'
    return "-"

def try_base64_variants(s):
    if not s or len(s) < 4: return None
    s = s.strip()
    if s.startswith('<') and s.endswith('>'): s = s[1:-1]
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        for pad in range(0,4):
            try:
                cand = s + ('=' * pad)
                decoded = decoder(cand)
                try:
                    text = decoded.decode('utf-8', errors='ignore')
                except Exception:
                    continue
                if text and text.strip():
                    return text
            except Exception:
                continue
    return None

def find_subid_in_text(txt):
    if not txt: return None
    m = ID_RE.search(txt)
    return m.group(1) if m else None

def format_date_to_ist_string(raw_date):
    if not raw_date: return "-", None
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
    msg_id_raw = decode_mime_words(msg.get("Message-ID", "") or msg.get("Message-Id", "") or "")
    if msg_id_raw:
        tokens = re.split(r'[_\s]+', msg_id_raw)
        for t in tokens:
            maybe = find_subid_in_text(t)
            if maybe: return maybe, map_id_to_type(maybe)
            decoded = try_base64_variants(t)
            if decoded:
                m2 = find_subid_in_text(decoded)
                if m2: return m2, map_id_to_type(m2)
    headers_str = " ".join(f"{h}:{v}" for h,v in msg.items())
    maybe = find_subid_in_text(headers_str)
    if maybe: return maybe, map_id_to_type(maybe)
    try:
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain","text/html"):
                payload = part.get_payload(decode=True)
                if not payload: continue
                try:
                    text = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
                except Exception:
                    text = str(payload)
                maybe = find_subid_in_text(text)
                if maybe: return maybe, map_id_to_type(maybe)
                tokens = re.split(r'[^A-Za-z0-9_\-+/=]', text)
                for t in tokens:
                    if len(t) < 12: continue
                    dec = try_base64_variants(t)
                    if dec:
                        m2 = find_subid_in_text(dec)
                        if m2: return m2, map_id_to_type(m2)
    except Exception:
        pass
    return None, "-"

def parse_fetch_parts_for_uid_and_date(fetch_response_parts) -> List[tuple]:
    results = []
    for part in fetch_response_parts:
        if not isinstance(part, tuple): continue
        header_bytes, body_bytes = part[0], part[1]
        try:
            meta = header_bytes.decode('utf-8', errors='ignore')
        except Exception:
            try:
                meta = str(header_bytes)
            except Exception:
                meta = ''
        uid_match = re.search(r'UID\s+(\d+)', meta)
        uid_str = uid_match.group(1) if uid_match else None
        raw_date = ""
        if body_bytes:
            try:
                body_text = body_bytes.decode('utf-8', errors='ignore')
            except Exception:
                body_text = str(body_bytes)
            m = re.search(r'Date:\s*(.+)', body_text, flags=re.I)
            if m:
                raw_date = m.group(1).strip()
        if uid_str:
            results.append((uid_str, raw_date))
    return results

# ---------- Core fetch function (Optimized for O(1) Incremental & Limits) ----------
def fetch_inbox_emails_single(email_addr, password, last_uid=None, fetch_type='incremental', fetch_n=None, fetch_unit='emails', uid_scan_limit=UID_SCAN_LIMIT, chunk_size=CHUNK_SIZE):
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
        if fetch_type == 'incremental' and last_uid is not None:
            next_uid = int(last_uid) + 1
            status, data = imap.uid('search', None, f'UID {next_uid}:*')
            if status == 'OK' and data and data[0]:
                raw_uids = data[0].split()
                # Ensure IMAP doesn't return the highest UID if sequence is out of bounds
                uids = [u for u in raw_uids if int(u.decode()) >= next_uid]
                
        elif fetch_unit == 'emails' and fetch_n:
            status, data = imap.uid('search', None, 'ALL')
            if status == 'OK' and data and data[0]:
                all_uids = data[0].split()
                uids = all_uids[-int(fetch_n):]
                
        elif fetch_unit in ('hours','minutes') and fetch_n:
            ist = pytz.timezone("Asia/Kolkata")
            now_ist = datetime.datetime.now(ist).replace(tzinfo=None)
            if fetch_unit == 'hours':
                cutoff = now_ist - datetime.timedelta(hours=int(fetch_n))
            else:
                cutoff = now_ist - datetime.timedelta(minutes=int(fetch_n))

            status, data = imap.uid('search', None, 'ALL')
            if status == 'OK' and data and data[0]:
                all_uids = data[0].split()
                uids_to_check = all_uids[-uid_scan_limit:] if len(all_uids) > uid_scan_limit else all_uids
                matched_uids = []
                for i in range(0, len(uids_to_check), chunk_size):
                    chunk = uids_to_check[i:i+chunk_size]
                    uid_seq = b','.join(chunk)
                    try:
                        res, fdata = imap.uid('fetch', uid_seq, '(BODY.PEEK[HEADER.FIELDS (DATE)])')
                    except Exception:
                        for u in chunk:
                            try:
                                uid_str = u.decode()
                                r, md = imap.uid('fetch', uid_str, '(BODY.PEEK[HEADER.FIELDS (DATE)])')
                                if r != 'OK' or not md: continue
                                parsed = parse_fetch_parts_for_uid_and_date(md)
                                for (uid_s, raw_date) in parsed:
                                    if not raw_date: continue
                                    _, dt = format_date_to_ist_string(raw_date)
                                    if dt and dt >= cutoff:
                                        matched_uids.append(uid_s.encode())
                            except Exception:
                                continue
                        continue

                    parsed = parse_fetch_parts_for_uid_and_date(fdata)
                    for uid_str, raw_date in parsed:
                        if not raw_date: continue
                        _, dt = format_date_to_ist_string(raw_date)
                        if dt and dt >= cutoff:
                            matched_uids.append(uid_str.encode())
                uids = matched_uids
        else:
            ist = pytz.timezone("Asia/Kolkata")
            today_ist = datetime.datetime.now(ist).strftime("%d-%b-%Y")
            status, data = imap.uid('search', None, f'(SINCE "{today_ist}")')
            if status == 'OK' and data and data[0]:
                uids = data[0].split()

        if not uids:
            imap.logout()
            return pd.DataFrame(results), new_last_uid

        # Batch-fetch matched uids
        fetch_uid_bytes = uids
        for i in range(0, len(fetch_uid_bytes), chunk_size):
            chunk = fetch_uid_bytes[i:i+chunk_size]
            uid_seq = b','.join(chunk)
            try:
                res, fdata = imap.uid('fetch', uid_seq, '(BODY.PEEK[HEADER])')
            except Exception:
                for u in chunk:
                    try:
                        uid_s = u.decode()
                        r2, md2 = imap.uid('fetch', uid_s, '(BODY.PEEK[HEADER])')
                        if r2 != 'OK' or not md2 or not isinstance(md2[0], tuple): continue
                        msg = email.message_from_bytes(md2[0][1])
                        subject = decode_mime_words(msg.get("Subject","No Subject"))
                        from_h = decode_mime_words(msg.get("From","-"))
                        domain = extract_domain_from_address(from_h)
                        spf, dkim, dmarc = extract_auth_results_from_headers(msg)
                        sub_id, id_type = extract_subid_from_msg(msg)
                        raw_date = msg.get("Date","")
                        formatted, dt = format_date_to_ist_string(raw_date)
                        results.append({
                            "UID": uid_s,
                            "Domain": domain, "Subject": subject, "From": from_h,
                            "Message-ID": decode_mime_words(msg.get("Message-ID","")),
                            "Date": formatted, "Date_dt": dt,
                            "Sub ID": sub_id or "-", "Type": id_type,
                            "SPF": spf, "DKIM": dkim, "DMARC": dmarc
                        })
                        if new_last_uid is None or (uid_s.isdigit() and int(uid_s) > int(new_last_uid)):
                            new_last_uid = uid_s
                    except Exception:
                        continue
                continue

            for part in fdata:
                if not isinstance(part, tuple): continue
                hdr_bytes = part[1]
                try:
                    msg = email.message_from_bytes(hdr_bytes)
                except Exception:
                    continue
                uid_found = None
                try:
                    meta = part[0].decode('utf-8', errors='ignore')
                    m = re.search(r'UID\s+(\d+)', meta)
                    if m: uid_found = m.group(1)
                except Exception:
                    uid_found = None
                    
                subject = decode_mime_words(msg.get("Subject", "No Subject"))
                from_h = decode_mime_words(msg.get("From", "-"))
                domain = extract_domain_from_address(from_h)
                spf, dkim, dmarc = extract_auth_results_from_headers(msg)
                sub_id, id_type = extract_subid_from_msg(msg)
                raw_date = msg.get("Date", "")
                formatted, dt = format_date_to_ist_string(raw_date)
                uid_str = uid_found if uid_found else None
                if uid_str is None: continue
                
                results.append({
                    "UID": uid_str,
                    "Domain": domain, "Subject": subject, "From": from_h,
                    "Message-ID": decode_mime_words(msg.get("Message-ID","")),
                    "Date": formatted, "Date_dt": dt,
                    "Sub ID": sub_id or "-", "Type": id_type,
                    "SPF": spf, "DKIM": dkim, "DMARC": dmarc
                })
                if new_last_uid is None or (uid_str.isdigit() and int(uid_str) > int(new_last_uid)):
                    new_last_uid = uid_str

        imap.logout()

    except Exception as e:
        # Pass exception back to the worker to handle thread-safely
        raise Exception(f"IMAP Error: {e}")

    df = pd.DataFrame(results)
    return df, new_last_uid

# ---------- Styling ----------
def highlight_new_rows(row):
    return ['background-color: #90EE90'] * len(row) if row.get("is_new", False) else [''] * len(row)

def highlight_presence_row(row):
    try:
        if str(row.get("Auth", "")).lower() != "pass":
            style = 'background-color: rgba(255, 0, 0, 0.15)'
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
edited_df = st.data_editor(st.session_state.creds_df, num_rows="dynamic", column_config=column_config, key="editor", use_container_width=True, hide_index=True)
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
def process_fetch(fetch_type, fetch_n=None, fetch_unit='emails'):
    any_run = False
    
    # 1. Strip 'is_new' status globally before kicking off fresh fetch
    for email_addr, mailbox in st.session_state.mailbox_data.items():
        if "is_new" in mailbox["df"].columns:
            mailbox["df"]["is_new"] = False

    futures = []
    errors = []
    
    # 2. Spawn concurrent fetch threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for i, r in st.session_state.creds_df.iterrows():
            email_addr = r.get("Email","").strip()
            pwd = r.get("Password","").strip()
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
            df_new["is_new"] = True # Only this exact batch gets marked as new
            mailbox = st.session_state.mailbox_data[email_addr]
            mailbox["df"] = pd.concat([mailbox["df"], df_new], ignore_index=True).drop_duplicates(subset=["UID"], keep='last')
            mailbox["last_uid"] = new_uid

    if errors:
        for error in errors:
            st.error(error)

    return any_run

# ---------- One-line control bar ----------
st.markdown("---")
col_f1, col_f2, col_f3, col_f4 = st.columns([1.2, 1.2, 2.5, 1.2])

with col_f1:
    if st.button("🔄 Fetch New (incremental)"):
        ok = process_fetch('incremental')
        st.success("Fetched incremental emails." if ok else "No new emails found.")

with col_f2:
    fetch_n = st.number_input("N", min_value=1, value=100, step=1, label_visibility="collapsed", key="compact_fetch_n2")
    fetch_unit = st.selectbox("Unit", ["emails", "hours", "minutes"], index=2, label_visibility="collapsed", key="compact_unit2")
    if st.button("📥 Fetch Last N"):
        ok = process_fetch('last_n', fetch_n=fetch_n, fetch_unit=fetch_unit)
        st.success(f"Fetched last {fetch_n} {fetch_unit}." if ok else "No new emails found.")

with col_f3:
    non_empty = [r for _, r in st.session_state.creds_df.iterrows() if r.get("Email","").strip()]
    avail = max(1, len(non_empty))
    default_n = 4 if avail >=4 else avail
    required_accounts_count = st.number_input("Require Sub-ID presence in at least N accounts", min_value=1, max_value=avail, value=default_n, step=1, key="req_n")

with col_f4:
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
                st.metric(label=em.split('@')[0], value=total, delta=f"{newc} New" if newc>0 else None)

st.markdown("---")

# ---------- Build presence & asset maps ----------
all_keys = set()
email_presence_map = {}
new_email_keys = set()
valid_emails = [r["Email"] for _, r in st.session_state.creds_df.iterrows() if r["Email"] in st.session_state.mailbox_data]

asset_map = {} 

for email_addr in valid_emails:
    df_acc = st.session_state.mailbox_data[email_addr]["df"]
    keys = set()
    for _, row in df_acc.iterrows():
        key = (row["Domain"], row["Subject"], row["From"], row["SPF"], row["DKIM"], row["DMARC"], row.get("Sub ID","-"))
        keys.add(key)
        if row.get("is_new", False):
            new_email_keys.add(key)
        asset_key = (row.get("Domain","-"), row.get("From","-"), row.get("Subject","-"))
        asset = asset_map.setdefault(asset_key, {"accounts": set(), "subids": set(), "rows": []})
        asset["accounts"].add(email_addr)
        sid = row.get("Sub ID","-")
        if sid and sid != "-":
            asset["subids"].add(sid)
        asset["rows"].append({
            "account": email_addr,
            "UID": row.get("UID"),
            "Message-ID": row.get("Message-ID"),
            "Date": row.get("Date"),
            "Date_dt": row.get("Date_dt"),
            "Sub ID": sid or "-",
            "SPF": row.get("SPF"),
            "DKIM": row.get("DKIM"),
            "DMARC": row.get("DMARC"),
            "is_new": bool(row.get("is_new", False))
        })
    email_presence_map[email_addr] = keys
    all_keys.update(keys)

# ---------- TOP: Sub-ID table ----------
st.subheader(f"🔎 Sub-ID Consensus (≥ {required_accounts_count} accounts)")

subid_rows = []
for (domain, from_val, subject), info in asset_map.items():
    if len(info["accounts"]) < required_accounts_count:
        continue
    for subid in sorted(list(info["subids"])):
        subid_rows_for_asset = [r for r in info["rows"] if (r.get("Sub ID") or "-") == subid]
        subid_accounts = {r["account"] for r in subid_rows_for_asset}
        if len(subid_accounts) < required_accounts_count:
            continue

        all_auth_pass = True
        for r in subid_rows_for_asset:
            if not (str(r.get("SPF","")).lower() == "pass" and str(r.get("DKIM","")).lower() == "pass" and str(r.get("DMARC","")).lower() == "pass"):
                all_auth_pass = False
                break
        if not all_auth_pass:
            continue

        latest_dt = None
        latest_str = "-"
        any_new = False
        for r in subid_rows_for_asset:
            dt = r.get("Date_dt")
            if dt is not None and (latest_dt is None or dt > latest_dt):
                latest_dt = dt
                latest_str = r.get("Date") or latest_str
            if r.get("is_new", False):
                any_new = True

        row = {"Domain": domain, "From": from_val, "Subject": subject, "Sub ID": subid, "Time (IST)": latest_str, "is_new": any_new}
        for em in valid_emails:
            row[em.split('@')[0]] = "✅" if em in subid_accounts else "❌"
        subid_rows.append((latest_dt, row))

subid_rows_sorted = [r for _,r in sorted(subid_rows, key=lambda x: (x[0] is None, x[0]), reverse=True)]
if subid_rows_sorted:
    subid_df = pd.DataFrame(subid_rows_sorted)
    per_acc_cols = [e.split('@')[0] for e in valid_emails]
    display_cols = ["Domain","From","Subject","Sub ID","Time (IST)"] + per_acc_cols + ["is_new"]
    subid_df = subid_df.reindex(columns=display_cols, fill_value="-")
    st.dataframe(subid_df.style.apply(highlight_new_rows, axis=1), hide_index=True, column_config={"is_new": None}, use_container_width=True)
else:
    st.info(f"No Sub-IDs that meet the threshold of {required_accounts_count} accounts with all auths passing.")

st.markdown("---")

# ---------- MIDDLE: Presence table ----------
qualifying_subids = {}
for (domain, from_val, subject), info in asset_map.items():
    if len(info["accounts"]) < required_accounts_count:
        continue
    for subid in info["subids"]:
        subid_rows_for_asset = [r for r in info["rows"] if (r.get("Sub ID") or "-") == subid]
        subid_accounts = {r["account"] for r in subid_rows_for_asset}
        if len(subid_accounts) >= required_accounts_count:
            qualifying_subids.setdefault((domain, from_val, subject), []).append(subid)

rows = []
if all_keys:
    sorted_keys = sorted(list(all_keys), key=lambda k: (k not in new_email_keys, k[0], k[1]))
    for (domain, subject, from_val, spf, dkim, dmarc, subid) in sorted_keys:
        latest_dt = None
        latest_str = "-"
        auth_pass_for_row = True
        for em in valid_emails:
            df_acc = st.session_state.mailbox_data[em]["df"]
            matches = df_acc[
                (df_acc["Domain"]==domain) & (df_acc["Subject"]==subject) & (df_acc["From"]==from_val) & (df_acc.get("Sub ID","-")==subid)
            ]
            for _, m in matches.iterrows():
                dt = m.get("Date_dt")
                if dt is not None and (latest_dt is None or dt > latest_dt):
                    latest_dt = dt
                    latest_str = m.get("Date") or latest_str
                if not (str(m.get("SPF","")).lower() == "pass" and str(m.get("DKIM","")).lower() == "pass" and str(m.get("DMARC","")).lower() == "pass"):
                    auth_pass_for_row = False

        qual_key = (domain, from_val, subject)
        qual_list = qualifying_subids.get(qual_key, [])
        subids_cell = ", ".join(qual_list) if qual_list else "-"
        row = {
            "Domain": domain, "From": from_val, "Subject": subject, "Sub ID (raw)": subid,
            "Time (IST)": latest_str, "Auth": "Pass" if auth_pass_for_row else "Fail",
            "Sub IDs (qualifying)": subids_cell,
            "is_new": (domain, subject, from_val, spf, dkim, dmarc, subid) in new_email_keys,
            "Date_dt_sort": latest_dt
        }
        for em in valid_emails:
            row[em.split('@')[0]] = "✅" if (domain, subject, from_val, spf, dkim, dmarc, subid) in email_presence_map[em] else "❌"
        rows.append(row)
    
    presence_df = pd.DataFrame(rows)
    if "Date_dt_sort" in presence_df.columns:
        presence_df = presence_df.sort_values(by=["Date_dt_sort"], ascending=False, na_position='last', ignore_index=True)
        
    st.subheader("📋 Email Presence Table (Newest on Top)")
    if not presence_df.empty:
        per_account_cols = [e.split('@')[0] for e in valid_emails]
        display_cols = ["Domain","From","Subject","Sub ID (raw)","Time (IST)"] + per_account_cols + ["Sub IDs (qualifying)","Auth","is_new"]
        presence_df = presence_df.reindex(columns=display_cols, fill_value="-")
        st.dataframe(presence_df.style.apply(highlight_presence_row, axis=1), hide_index=True, column_config={"is_new": None}, use_container_width=True)
    else:
        st.info("No presence rows to show.")
else:
    st.info("No emails found in the active accounts.")

st.markdown("---")

# ---------- Raw per-account messages ----------
with st.expander("Show Individual Raw Messages"):
    for em in valid_emails:
        mailbox = st.session_state.mailbox_data[em]
        st.markdown(f"**{em}** — Stored: {len(mailbox['df'])}")
        if not mailbox["df"].empty:
            df_to_show = mailbox["df"].copy()
            df_to_show['UID_int'] = pd.to_numeric(df_to_show['UID'], errors='coerce')
            sorted_show = df_to_show.sort_values(by=["is_new","Date_dt","UID_int"], ascending=[False,False,False])
            st.dataframe(sorted_show.drop(columns=['UID_int']).style.apply(highlight_new_rows, axis=1), hide_index=True, use_container_width=True)
