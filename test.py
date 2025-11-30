import streamlit as st
import imaplib
import email
from email.header import decode_header
import datetime
import re
import pandas as pd
import pytz
import base64
import binascii

# ---------- Page Setup ----------
st.set_page_config(page_title="Dynamic Multi-Account Inbox", layout="wide")
st.title("📧 Dynamic Multi-Account Inbox Comparator")

# ---------- Robust Session State Initialization ----------
if "creds_df" not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{"Email": "", "Password": ""}])

if "mailbox_data" not in st.session_state:
    st.session_state.mailbox_data = {}

# Keep a one-word tag in session state (user requested single-word input)
if "subid_tag" not in st.session_state:
    st.session_state.subid_tag = ""

def get_empty_mailbox_structure():
    return {
        "last_uid": None,
        "df": pd.DataFrame(columns=["UID", "Domain", "Subject", "From", "Message-ID", "Sub ID", "Type", "SPF", "DKIM", "DMARC", "is_new"])
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

# ---------- Sub-ID Extraction Logic ----------
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

# ---------- Fetch Function with Sub-ID integrated ----------
def fetch_inbox_emails_single(email_addr, password, last_uid=None, fetch_n=None):
    results = []
    new_last_uid = last_uid
    try:
        email_addr = email_addr.strip()
        password = password.strip()
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_addr, password)
        imap.select("inbox")
        uids = []
        if last_uid:
            try:
                criteria = f'(UID {int(last_uid)+1}:*)'
                status, data = imap.uid('search', None, criteria)
                if status == 'OK' and data and data[0]:
                    uids = data[0].split()
            except Exception:
                pass
        elif fetch_n:
            status, data = imap.uid('search', None, 'ALL')
            if status == 'OK' and data and data[0]:
                all_uids = data[0].split()
                if len(all_uids) > 0:
                    uids = all_uids[-int(fetch_n):]
        else:
            ist = pytz.timezone('Asia/Kolkata')
            today_ist = datetime.datetime.now(ist).strftime("%d-%b-%Y")
            status, data = imap.uid('search', None, f'(SINCE "{today_ist}")')
            if status == 'OK' and data and data[0]:
                uids = data[0].split()

        for uid in uids:
            if not uid: continue
            uid_dec = uid.decode()
            res, msg_data = imap.uid('fetch', uid_dec, '(BODY.PEEK[HEADER])')
            if res == 'OK' and isinstance(msg_data[0], tuple):
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

def highlight_new_rows(row):
    return ['background-color: #90EE90'] * len(row) if row.get("is_new", False) else [''] * len(row)

# ---------- Account Input UI ----------
st.markdown("### 📋 Account Credentials")
st.info("Add as many accounts as you need. Passwords are required (App Passwords recommended for Gmail).")

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

# ---------- Sub-ID threshold input and one-word Tag placed beside fetch buttons ----------
st.markdown("---")
col_left, col_mid, col_right, col_tag = st.columns([1,1,1,1])

# Tag (single word) placed aside with the fetch buttons
with col_tag:
    tag_input = st.text_input("Tag (one word)", value=st.session_state.subid_tag, help="Single word tag (will keep only first token).")
    # keep only first token if user pasted multiple words
    token = tag_input.strip().split()[0] if tag_input.strip() else ""
    st.session_state.subid_tag = token

# Count how many non-empty email rows we have available
non_empty_creds = [r for i, r in st.session_state.creds_df.iterrows() if r.get("Email", "").strip()]
available_accounts = max(1, len(non_empty_creds))

with col_left:
    # placeholder (Fetch controls are below but visually this aligns inputs)
    st.write("")

# The threshold input (kept here so it sits near the fetch buttons visually)
required_accounts_count = st.number_input(
    "Require Sub-ID presence in at least N accounts (set N):",
    min_value=1,
    max_value=available_accounts,
    value=min(2, available_accounts),
    step=1,
    help="Only show Sub-IDs for message assets that appear in at least this many accounts."
)

if required_accounts_count > available_accounts:
    st.warning(f"You set N = {required_accounts_count}, but only {available_accounts} account(s) have non-empty Email. Please adjust N or add accounts.")

# ---------- Fetch Controls (buttons) ----------
st.markdown("---")
colA, colB, colC = st.columns([1, 1, 1])

def process_fetch(fetch_type, fetch_n=None):
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
            else fetch_inbox_emails_single(email_addr, pwd, fetch_n=int(fetch_n))
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
        if process_fetch('incremental'): st.success("Fetched incremental emails.")
        else: st.warning("No valid credentials found in table.")

with colB:
    fetch_n = st.number_input("Fetch last N emails", min_value=1, value=10, step=1, key="fetch_n_input")
    if st.button("📥 Fetch Last N Emails"):
        if process_fetch('last_n', fetch_n): st.success(f"Fetched last {fetch_n} emails.")
        else: st.warning("No valid credentials found in table.")

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
            new_count = data["df"]["is_new"].sum() if "is_new" in data["df"].columns else 0
            short_name = email_key.split('@')[0]
            with m_cols[i]:
                st.metric(label=short_name, value=total_count, delta=f"{new_count} New" if new_count > 0 else None)

st.markdown("---")

# ---------- Email Presence Table (exactly as before) ----------
all_keys = set()
email_presence_map = {}  # { email_address: set(message_keys) }
new_email_keys = set()
valid_emails = [r["Email"] for i, r in st.session_state.creds_df.iterrows() if r["Email"] in st.session_state.mailbox_data]

for email_addr in valid_emails:
    df_acc = st.session_state.mailbox_data[email_addr]["df"]
    keys = set()
    for _, row in df_acc.iterrows():
        # original presence key (unchanged)
        msg_key = (row["Domain"], row["Subject"], row["From"], row["SPF"], row["DKIM"], row["DMARC"], row.get("Sub ID", "-"))
        keys.add(msg_key)
        if row.get("is_new", False):
            new_email_keys.add(msg_key)
    email_presence_map[email_addr] = keys
    all_keys.update(keys)

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

    st.subheader("📋 Email Presence Table (Newest on Top)")
    if rows:
        presence_df = pd.DataFrame(rows)
        st.dataframe(presence_df.style.apply(highlight_new_rows, axis=1), hide_index=True, column_config={"is_new": None})
else:
    st.info("No emails found in the active accounts.")

st.markdown("---")

# ---------- NEW: Sub-ID Matches (only assets present in ≥ N accounts AND have >=1 Sub-ID) ----------
st.subheader(f"🔎 Sub-ID Matches (assets present in ≥ {required_accounts_count} accounts AND having Sub-ID(s))")

# Build a mapping from asset-key (Domain, From, Subject) -> details across accounts
asset_map = {}  # {(domain, from, subject): {"accounts": set(), "subids": set(), "rows": [row dicts]}}
for email_addr in valid_emails:
    df_acc = st.session_state.mailbox_data[email_addr]["df"]
    for _, r in df_acc.iterrows():
        asset_key = (r.get("Domain", "-"), r.get("From", "-"), r.get("Subject", "-"))
        asset = asset_map.setdefault(asset_key, {"accounts": set(), "subids": set(), "rows": []})
        asset["accounts"].add(email_addr)
        sid = r.get("Sub ID", "-")
        if sid and sid != "-":
            asset["subids"].add(sid)
        asset["rows"].append({
            "account": email_addr,
            "UID": r.get("UID"),
            "Message-ID": r.get("Message-ID"),
            "Sub ID": sid or "-",
            "Type": r.get("Type", "-"),
            "SPF": r.get("SPF"),
            "DKIM": r.get("DKIM"),
            "DMARC": r.get("DMARC")
        })

# Now filter assets that meet the threshold AND have at least one Sub-ID
subid_rows = []
for (domain, from_val, subject), info in asset_map.items():
    present_count = len(info["accounts"])
    has_subids = len(info["subids"]) > 0
    if present_count >= required_accounts_count and has_subids:
        subid_list = sorted(list(info["subids"]))
        accounts_list = sorted(list(info["accounts"]))
        row = {
            "Domain": domain,
            "From": from_val,
            "Subject": subject,
            "Present In (Count)": present_count,
            "Accounts": ", ".join([a.split('@')[0] for a in accounts_list]),
            "Sub IDs (all)": ", ".join(subid_list) if subid_list else "-"
        }
        for email_addr in valid_emails:
            header = email_addr.split('@')[0]
            row[header] = "✅" if email_addr in info["accounts"] else "❌"
        subid_rows.append(row)

if subid_rows:
    subid_df = pd.DataFrame(subid_rows)
    subid_df = subid_df.sort_values(by=["Present In (Count)", "Domain"], ascending=[False, True], ignore_index=True)
    st.dataframe(subid_df, use_container_width=True)
else:
    st.info(f"No assets found that both contain Sub-IDs and appear in at least {required_accounts_count} accounts.")

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
