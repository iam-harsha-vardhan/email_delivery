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
import binascii

# ---------- Page Setup ----------
st.set_page_config(page_title="Dynamic Multi-Account Inbox", layout="wide")
st.title("📧 Dynamic Multi-Account Inbox Comparator")

# ---------- Session State Initialization ----------
if "creds_df" not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{"Email": "", "Password": ""}])

if "mailbox_data" not in st.session_state:
    st.session_state.mailbox_data = {}

if "subid_tag" not in st.session_state:
    st.session_state.subid_tag = ""

# ---------- Helper: empty mailbox structure ----------
def get_empty_mailbox_structure():
    return {
        "last_uid": None,
        "df": pd.DataFrame(columns=[
            "UID", "Domain", "Subject", "From", "Message-ID", "Sub ID", "Type", "SPF", "DKIM", "DMARC", "is_new"
        ])
    }

# ---------- Utilities ----------
def decode_mime_words(s):
    if not s: return ""
    decoded = ''
    for word, enc in decode_header(s):
        if isinstance(word, bytes):
            try:
                if enc and enc.lower() not in ["unknown-8bit", "x-unknown"]:
                    decoded += word.decode(enc, errors="ignore")
                else:
                    decoded += word.decode("utf-8", errors="ignore")
            except Exception:
                decoded += word.decode("utf-8", errors="ignore")
        else:
            decoded += word
    return decoded.strip()

def extract_domain_from_address(address):
    if not address: return "-"
    m = re.search(r'@([\w\.-]+)', address)
    return m.group(1).lower() if m else "-"

def extract_auth_results_from_headers(msg):
    auth_header = msg.get("Authentication-Results", "") or " ".join(f"{h}: {v}" for h, v in msg.items())
    spf = dkim = dmarc = 'neutral'
    m_spf = re.search(r'spf=(\w+)', auth_header, re.I)
    m_dkim = re.search(r'dkim=(\w+)', auth_header, re.I)
    m_dmarc = re.search(r'dmarc=(\w+)', auth_header, re.I)
    if m_spf: spf = m_spf.group(1).lower()
    if m_dkim: dkim = m_dkim.group(1).lower()
    if m_dmarc: dmarc = m_dmarc.group(1).lower()
    return spf, dkim, dmarc

# ---------- Sub-ID extraction ----------
ID_RE = re.compile(r'\b(GRM-[A-Za-z0-9\-]+|GMFP-[A-Za-z0-9\-]+|GTC-[A-Za-z0-9\-]+|GRTC-[A-Za-z0-9\-]+)\b', re.I)

def map_id_to_type(sub_id):
    if not sub_id: return "-"
    lid = sub_id.lower()
    if lid.startswith('grm'):
        return 'FPR'
    if lid.startswith('gmfp'):
        return 'FP'
    if lid.startswith('gtc'):
        return 'FPTC'
    if lid.startswith('grtc'):
        return 'FPRTC'
    return "-"

def try_base64_variants(s):
    """Try standard and urlsafe base64 decode with small paddings."""
    if not s or len(s) < 4:
        return None
    s = s.strip()
    if s.startswith('<') and s.endswith('>'):
        s = s[1:-1]
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        for pad in range(0, 4):
            try:
                candidate = s + ('=' * pad)
                decoded = decoder(candidate)
                try:
                    text = decoded.decode('utf-8', errors='ignore')
                except Exception:
                    continue
                if text and len(text.strip()) > 0:
                    return text
            except (binascii.Error, ValueError):
                continue
    return None

def find_subid_in_text(text):
    if not text:
        return None
    m = ID_RE.search(text)
    if m:
        return m.group(1)
    return None

def extract_subid_from_msg(msg):
    """Search Message-ID tokens, headers, and text parts for a Sub-ID. Returns (sub_id or None, type)."""
    # 1) Message-ID header tokens
    msg_id_raw = decode_mime_words(msg.get("Message-ID", "") or msg.get("Message-Id", "") or "")
    if msg_id_raw:
        tokens = re.split(r'[_\s]+', msg_id_raw)
        for token in tokens:
            maybe = find_subid_in_text(token)
            if maybe:
                return maybe, map_id_to_type(maybe)
            decoded = try_base64_variants(token)
            if decoded:
                maybe2 = find_subid_in_text(decoded)
                if maybe2:
                    return maybe2, map_id_to_type(maybe2)
    # 2) All headers combined
    headers_str = " ".join(f"{h}:{v}" for h, v in msg.items())
    maybe = find_subid_in_text(headers_str)
    if maybe:
        return maybe, map_id_to_type(maybe)
    # 3) Walk payloads
    try:
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        text = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
                    except Exception:
                        text = str(payload)
                    maybe = find_subid_in_text(text)
                    if maybe:
                        return maybe, map_id_to_type(maybe)
                    tokens = re.split(r'[^A-Za-z0-9_\-+/=]', text)
                    for token in tokens:
                        if len(token) < 12:
                            continue
                        decoded = try_base64_variants(token)
                        if decoded:
                            maybe2 = find_subid_in_text(decoded)
                            if maybe2:
                                return maybe2, map_id_to_type(maybe2)
    except Exception:
        pass
    return None, "-"

# ---------- Fetch function (supports last N emails / hours / minutes) ----------
def fetch_inbox_emails_single(email_addr, password, last_uid=None, fetch_n=None, fetch_unit='emails'):
    """
    fetch_unit: 'emails' (last N messages), 'hours' or 'minutes' (messages since now - N units)
    For hours/minutes, we fetch a bounded set of recent UIDs and then filter by Date header.
    """
    results = []
    new_last_uid = last_uid
    try:
        email_addr = email_addr.strip()
        password = password.strip()
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_addr, password)
        imap.select("inbox")

        uids = []

        # If incremental (last_uid provided), use UID since logic (ignoring fetch_n here)
        if last_uid and fetch_unit == 'emails' and fetch_n is None:
            try:
                criteria = f'(UID {int(last_uid)+1}:*)'
                status, data = imap.uid('search', None, criteria)
                if status == 'OK' and data and data[0]:
                    uids = data[0].split()
            except Exception:
                pass

        elif fetch_unit == 'emails' and fetch_n:
            # Fetch last N emails (as before)
            status, data = imap.uid('search', None, 'ALL')
            if status == 'OK' and data and data[0]:
                all_uids = data[0].split()
                if len(all_uids) > 0:
                    uids = all_uids[-int(fetch_n):]

        elif fetch_unit in ('hours', 'minutes') and fetch_n:
            # Compute cutoff in IST
            ist = pytz.timezone('Asia/Kolkata')
            now_ist = datetime.datetime.now(ist)
            if fetch_unit == 'hours':
                cutoff = now_ist - datetime.timedelta(hours=int(fetch_n))
            else:
                cutoff = now_ist - datetime.timedelta(minutes=int(fetch_n))
            # We'll fetch a bounded number of recent UIDs to avoid scanning entire mailbox.
            # Tune this LIMIT to your needs (lower -> faster, higher -> more coverage)
            UID_SCAN_LIMIT = 2000
            status, data = imap.uid('search', None, 'ALL')
            if status == 'OK' and data and data[0]:
                all_uids = data[0].split()
                # consider at most last UID_SCAN_LIMIT UIDs
                uids_to_check = all_uids[-UID_SCAN_LIMIT:] if len(all_uids) > UID_SCAN_LIMIT else all_uids
                # Now we'll iterate and include only those whose Date >= cutoff
                for uid in uids_to_check:
                    uid_dec = uid.decode()
                    res, msg_data = imap.uid('fetch', uid_dec, '(BODY.PEEK[HEADER.FIELDS (DATE SUBJECT FROM MESSAGE-ID)])')
                    if res != 'OK' or not msg_data or not isinstance(msg_data[0], tuple):
                        continue
                    try:
                        msg = email.message_from_bytes(msg_data[0][1])
                        raw_date = msg.get("Date", "")
                        if not raw_date:
                            continue
                        try:
                            msg_dt = parsedate_to_datetime(raw_date)
                            # convert to IST for comparison
                            ist_offset = pytz.timezone('Asia/Kolkata')
                            if msg_dt.tzinfo is None:
                                msg_dt = msg_dt.replace(tzinfo=datetime.timezone.utc)
                            msg_dt_ist = msg_dt.astimezone(ist_offset).replace(tzinfo=None)
                        except Exception:
                            # if parsing fails, skip
                            continue
                        if msg_dt_ist >= cutoff.replace(tzinfo=None):
                            uids.append(uid)
                    except Exception:
                        continue

        else:
            # Default: today's emails (same as original)
            ist = pytz.timezone('Asia/Kolkata')
            today_ist = datetime.datetime.now(ist).strftime("%d-%b-%Y")
            status, data = imap.uid('search', None, f'(SINCE "{today_ist}")')
            if status == 'OK' and data and data[0]:
                uids = data[0].split()

        # If uids not set above (e.g., incremental without last_uid), ensure it's an iterable
        if not uids:
            uids = []

        # Fetch headers for selected UIDs (if we already fetched for hours/minutes we only added UIDs that match)
        for uid in uids:
            if not uid: continue
            uid_dec = uid.decode()
            # If we previously fetched a small header snippet for time filtering, we may re-fetch full header here
            res, msg_data = imap.uid('fetch', uid_dec, '(BODY.PEEK[HEADER])')
            if res == 'OK' and msg_data and isinstance(msg_data[0], tuple):
                msg = email.message_from_bytes(msg_data[0][1])
                subject = decode_mime_words(msg.get("Subject", "No Subject"))
                from_header = decode_mime_words(msg.get("From", "-"))
                domain = extract_domain_from_address(from_header)
                spf, dkim, dmarc = extract_auth_results_from_headers(msg)
                sub_id, id_type = extract_subid_from_msg(msg)
                results.append({
                    "UID": uid_dec,
                    "Domain": domain,
                    "Subject": subject,
                    "From": from_header,
                    "Message-ID": decode_mime_words(msg.get("Message-ID", "")),
                    "Sub ID": sub_id or "-",
                    "Type": id_type,
                    "SPF": spf,
                    "DKIM": dkim,
                    "DMARC": dmarc
                })
                if new_last_uid is None or (uid_dec.isdigit() and int(uid_dec) > int(new_last_uid)):
                    new_last_uid = uid_dec

        imap.logout()

    except imaplib.IMAP4.error as e:
        st.error(f"IMAP error for {email_addr}: {e}")
        return pd.DataFrame(), last_uid
    except Exception as e:
        st.error(f"Error fetching {email_addr}: {e}")
        return pd.DataFrame(), last_uid

    return pd.DataFrame(results), new_last_uid

# ---------- Row highlight for new fetches ----------
def highlight_new_rows(row):
    return ['background-color: #90EE90'] * len(row) if row.get("is_new", False) else [''] * len(row)

# ---------- Account Input UI ----------
st.markdown("### 📋 Account Credentials")
st.info("Add accounts. Use App Passwords for Gmail.")

column_config = {
    "Email": st.column_config.TextColumn("Email Address", width="medium", required=True),
    "Password": st.column_config.TextColumn("App Password", width="medium", required=True),
}

edited_df = st.data_editor(
    st.session_state.creds_df,
    num_rows="dynamic",
    column_config=column_config,
    key="editor_changes",
    use_container_width=True,
    hide_index=True
)
st.session_state.creds_df = edited_df

# ---------- Tag input + threshold (positioned beside fetch controls) ----------
st.markdown("---")
col_left, col_mid, col_right, col_tag = st.columns([1,1,1,1])

with col_tag:
    tag_input = st.text_input("Tag (one word)", value=st.session_state.subid_tag, help="Single word tag (keeps only first token).")
    token = tag_input.strip().split()[0] if tag_input.strip() else ""
    st.session_state.subid_tag = token

# Count how many non-empty email rows we have available
non_empty_creds = [r for i, r in st.session_state.creds_df.iterrows() if r.get("Email", "").strip()]
available_accounts = max(1, len(non_empty_creds))

required_accounts_count = st.number_input(
    "Require Sub-ID presence in at least N accounts (set N):",
    min_value=1,
    max_value=available_accounts,
    value=min(2, available_accounts),
    step=1,
    help="Only show Sub-IDs for assets that appear in at least this many accounts AND have Sub-IDs in ≥ N accounts."
)

if required_accounts_count > available_accounts:
    st.warning(f"You set N = {required_accounts_count}, but only {available_accounts} account(s) have non-empty Email. Adjust N or add accounts.")

# ---------- Fetch Controls (with Unit selector) ----------
st.markdown("---")
colA, colB, colC = st.columns([1, 1, 1])

# Put fetch_n and unit selection above the button area for clarity
with colB:
    fetch_n = st.number_input("Fetch last N", min_value=1, value=10, step=1, key="fetch_n_input")
    fetch_unit = st.selectbox("Units", options=["emails", "hours", "minutes"], index=0, help="Choose 'emails' (last N messages) or time window (last N hours/minutes).")

def process_fetch(fetch_type, fetch_n=None, fetch_unit='emails'):
    any_run = False
    for index, row in st.session_state.creds_df.iterrows():
        email_addr = row.get("Email", "").strip()
        pwd = row.get("Password", "").strip()
        if not email_addr or not pwd:
            continue
        if email_addr not in st.session_state.mailbox_data:
            st.session_state.mailbox_data[email_addr] = get_empty_mailbox_structure()
        current_data = st.session_state.mailbox_data[email_addr]
        if "is_new" in current_data["df"].columns:
            current_data["df"]["is_new"] = False
        any_run = True
        df_new, new_uid = (
            fetch_inbox_emails_single(email_addr, pwd, last_uid=current_data.get("last_uid"))
            if fetch_type == 'incremental'
            else fetch_inbox_emails_single(email_addr, pwd, fetch_n=int(fetch_n), fetch_unit=fetch_unit)
        )
        if not df_new.empty:
            df_new["is_new"] = True
            current_data["df"] = pd.concat([current_data["df"], df_new], ignore_index=True).drop_duplicates(subset=["UID"], keep='last')
            try:
                current_data["last_uid"] = str(current_data["df"]["UID"].astype(int).max())
            except:
                pass
    return any_run

with colA:
    if st.button("🔄 Fetch New Emails (incremental)"):
        if process_fetch('incremental'):
            st.success("Fetched incremental emails.")
        else:
            st.warning("No valid credentials found in table.")

with colB:
    if st.button("📥 Fetch Last N (by unit)"):
        # uses fetch_n and fetch_unit from inputs
        if process_fetch('last_n', fetch_n=fetch_n, fetch_unit=fetch_unit):
            st.success(f"Fetched messages for last {fetch_n} {fetch_unit}.")
        else:
            st.warning("No valid credentials found in table.")

with colC:
    if st.button("🗑️ Clear All Stored Data"):
        st.session_state.mailbox_data = {}
        st.success("Cleared all fetched emails (credentials preserved).")
        st.rerun()

# ---------- Email Counts ----------
st.markdown("### 📊 Email Counts per Account")
if not st.session_state.mailbox_data:
    st.write("No data fetched yet.")
else:
    active_emails = [k for k in st.session_state.mailbox_data.keys()]
    if active_emails:
        m_cols = st.columns(len(active_emails))
        for i, email_key in enumerate(active_emails):
            data = st.session_state.mailbox_data[email_key]
            total_count = len(data["df"])
            new_count = int(data["df"]["is_new"].sum()) if "is_new" in data["df"].columns else 0
            short_name = email_key.split('@')[0]
            with m_cols[i]:
                st.metric(label=short_name, value=total_count, delta=f"{new_count} New" if new_count > 0 else None)

st.markdown("---")

# ---------- Build presence keys and asset map (shared data structures) ----------
all_keys = set()
email_presence_map = {}  # { email_address: set(message_keys) }
new_email_keys = set()
valid_emails = [r["Email"] for i, r in st.session_state.creds_df.iterrows() if r["Email"] in st.session_state.mailbox_data]

# Asset map for Sub-ID consensus logic
asset_map = {}  # {(domain, from, subject): {"accounts": set(), "subids": set(), "subid_accounts": set(), "rows": []}}

for email_addr in valid_emails:
    df_acc = st.session_state.mailbox_data[email_addr]["df"]
    keys = set()
    for _, row in df_acc.iterrows():
        # presence key (unchanged)
        msg_key = (row["Domain"], row["Subject"], row["From"], row["SPF"], row["DKIM"], row["DMARC"], row.get("Sub ID", "-"))
        keys.add(msg_key)
        if row.get("is_new", False):
            new_email_keys.add(msg_key)
        # build asset_map
        asset_key = (row.get("Domain", "-"), row.get("From", "-"), row.get("Subject", "-"))
        asset = asset_map.setdefault(asset_key, {"accounts": set(), "subids": set(), "subid_accounts": set(), "rows": []})
        asset["accounts"].add(email_addr)
        sid = row.get("Sub ID", "-")
        if sid and sid != "-":
            asset["subids"].add(sid)
            asset["subid_accounts"].add(email_addr)
        asset["rows"].append({
            "account": email_addr,
            "UID": row.get("UID"),
            "Message-ID": row.get("Message-ID"),
            "Sub ID": sid or "-",
            "Type": row.get("Type", "-"),
            "SPF": row.get("SPF"),
            "DKIM": row.get("DKIM"),
            "DMARC": row.get("DMARC"),
            "is_new": bool(row.get("is_new", False))
        })
    email_presence_map[email_addr] = keys
    all_keys.update(keys)

# ---------- TOP: Sub-ID Consensus (full width) ----------
st.subheader(f"🔎 Sub-ID Consensus (≥ {required_accounts_count} accounts)")

subid_rows = []
for (domain, from_val, subject), info in asset_map.items():
    present_count = len(info["accounts"])
    subid_accounts_count = len(info["subid_accounts"])
    # Strict requirement: both presence and subid must reach the threshold
    if present_count >= required_accounts_count and subid_accounts_count >= required_accounts_count:
        subid_list = sorted(list(info["subids"]))
        accounts_list = sorted(list(info["accounts"]))
        asset_is_new = any(r.get("is_new", False) for r in info["rows"])
        row = {
            "Domain": domain,
            "From": from_val,
            "Subject": subject,
            "Present In (Count)": present_count,
            "Sub-ID Accounts (Count)": subid_accounts_count,
            "Accounts": ", ".join([a.split('@')[0] for a in accounts_list]),
            "Sub IDs (all)": ", ".join(subid_list) if subid_list else "-",
            "is_new": asset_is_new
        }
        for email_addr in valid_emails:
            header = email_addr.split('@')[0]
            row[header] = "✅" if email_addr in info["accounts"] else "❌"
        subid_rows.append(row)

if subid_rows:
    subid_df = pd.DataFrame(subid_rows)
    subid_df = subid_df.sort_values(by=["Sub-ID Accounts (Count)", "Present In (Count)", "Domain"], ascending=[False, False, True], ignore_index=True)
    st.dataframe(subid_df.style.apply(highlight_new_rows, axis=1), use_container_width=True)
else:
    st.info(f"No assets found that contain Sub-IDs in at least {required_accounts_count} accounts and are present in ≥ {required_accounts_count} accounts.")

st.markdown("---")

# ---------- MIDDLE: Email Presence Table (centered) ----------
rows = []
if all_keys:
    sorted_keys = sorted(list(all_keys), key=lambda k: (k not in new_email_keys, k[0], k[1]))
    for (domain, subject, from_val, spf, dkim, dmarc, subid) in sorted_keys:
        row_data = {
            "Domain": domain, "From": from_val, "Subject": subject,
            "Sub ID": subid,
            "Auth": "Pass" if all(res == 'pass' for res in [spf, dkim, dmarc]) else "Fail",
            "is_new": (domain, subject, from_val, spf, dkim, dmarc, subid) in new_email_keys
        }
        for email_addr in valid_emails:
            is_present = (domain, subject, from_val, spf, dkim, dmarc, subid) in email_presence_map[email_addr]
            col_header = email_addr.split('@')[0]
            row_data[col_header] = "✅" if is_present else "❌"
        rows.append(row_data)

    left_col, mid_col, right_col = st.columns([1, 8, 1])
    with mid_col:
        st.subheader("📋 Email Presence Table (Newest on Top)")
        presence_df = pd.DataFrame(rows)
        st.dataframe(presence_df.style.apply(highlight_new_rows, axis=1), hide_index=True, column_config={"is_new": None}, use_container_width=True)
else:
    st.info("No emails found in the active accounts.")

st.markdown("---")

# ---------- Individual Raw Data (unchanged) ----------
with st.expander("Show Individual Raw Messages"):
    for email_addr in valid_emails:
        data = st.session_state.mailbox_data[email_addr]
        st.markdown(f"**{email_addr}** — Stored: {len(data['df'])}")
        if not data["df"].empty:
            df_to_show = data["df"].copy()
            df_to_show['UID_int'] = pd.to_numeric(df_to_show['UID'], errors='coerce')
            sorted_df_to_show = df_to_show.sort_values(by=["is_new", "UID_int"], ascending=[False, False])
            st.dataframe(sorted_df_to_show.drop(columns=['UID_int']).style.apply(highlight_new_rows, axis=1), hide_index=True, column_config={"is_new": None})
