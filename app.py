import streamlit as st
import imaplib
import email
from email.header import decode_header
import datetime
import re
import pandas as pd
import pytz

# ---------- Page Setup ----------
st.set_page_config(page_title="Dynamic Multi-Account Inbox", layout="wide")
st.title("📧 Dynamic Multi-Account Inbox Comparator")

# ---------- Robust Session State Initialization ----------
# We store the credentials dataframe separately so the UI persists
if "creds_df" not in st.session_state:
    st.session_state.creds_df = pd.DataFrame(
        [{"Email": "", "Password": ""}], # Start with one empty row
    )

# We store fetched data in a dict keyed by Email Address
if "mailbox_data" not in st.session_state:
    st.session_state.mailbox_data = {}

def get_empty_mailbox_structure():
    return {
        "last_uid": None,
        "df": pd.DataFrame(columns=["UID", "Domain", "Subject", "From", "SPF", "DKIM", "DMARC", "is_new"])
    }

# ---------- Utilities ----------
def decode_mime_words(s):
    """Robust decoder for email headers."""
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
    auth_header = msg.get("Authentication-Results", "")
    spf = dkim = dmarc = 'neutral'
    m_spf = re.search(r'spf=(\w+)', auth_header, re.I)
    m_dkim = re.search(r'dkim=(\w+)', auth_header, re.I)
    m_dmarc = re.search(r'dmarc=(\w+)', auth_header, re.I)
    if m_spf: spf = m_spf.group(1).lower()
    if m_dkim: dkim = m_dkim.group(1).lower()
    if m_dmarc: dmarc = m_dmarc.group(1).lower()
    return spf, dkim, dmarc

def fetch_inbox_emails_single(email_addr, password, last_uid=None, fetch_n=None):
    results = []
    new_last_uid = last_uid
    try:
        email_addr = email_addr.strip()
        password = password.strip()
        
        # Connect to Gmail IMAP
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
            except Exception: pass
        elif fetch_n:
            status, data = imap.uid('search', None, 'ALL')
            if status == 'OK' and data and data[0]: 
                uids = data[0].split()[-int(fetch_n):]
        else:
            # Default: fetch today's emails if no specific instruction
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
                results.append({
                    "UID": uid_dec, "Domain": domain, "Subject": subject,
                    "From": from_header, "SPF": spf, "DKIM": dkim, "DMARC": dmarc
                })
                if new_last_uid is None or int(uid_dec) > int(new_last_uid):
                    new_last_uid = uid_dec
        imap.logout()
    except Exception as e:
        st.error(f"Error fetching {email_addr}: {e}")
        return pd.DataFrame(), last_uid # Return empty on fail

    return pd.DataFrame(results), new_last_uid

def highlight_new_rows(row):
    return ['background-color: #90EE90'] * len(row) if row.get("is_new", False) else [''] * len(row)

# ---------- Account Input UI (The "Mini Sheet") ----------
st.markdown("### 📋 Account Credentials")
st.info("Add as many accounts as you need. Passwords are required (App Passwords recommended for Gmail).")

# Configuration for the data editor to look nice
column_config = {
    "Email": st.column_config.TextColumn("Email Address", width="medium", required=True),
    "Password": st.column_config.TextColumn("App Password", width="medium", required=True),
}

# The Data Editor
edited_df = st.data_editor(
    st.session_state.creds_df,
    num_rows="dynamic",  # Allows adding/deleting rows
    column_config=column_config,
    key="editor_changes",
    use_container_width=True,
    hide_index=True
)

# Update session state with changes so they persist on rerun
st.session_state.creds_df = edited_df

# ---------- Fetch Controls ----------
st.markdown("---")
colA, colB, colC = st.columns([1, 1, 1])

def process_fetch(fetch_type, fetch_n=None):
    any_run = False
    
    # Loop through the rows in the "Mini Sheet"
    for index, row in st.session_state.creds_df.iterrows():
        email_addr = row.get("Email", "").strip()
        pwd = row.get("Password", "").strip()
        
        if not email_addr or not pwd:
            continue # Skip empty rows
            
        # Initialize storage for this email if not exists
        if email_addr not in st.session_state.mailbox_data:
            st.session_state.mailbox_data[email_addr] = get_empty_mailbox_structure()
        
        # Reset "is_new" flags for this account
        current_data = st.session_state.mailbox_data[email_addr]
        if "is_new" in current_data["df"].columns:
            current_data["df"]["is_new"] = False

        any_run = True
        
        # Perform Fetch
        df_new, new_uid = (
            fetch_inbox_emails_single(email_addr, pwd, last_uid=current_data.get("last_uid"))
            if fetch_type == 'incremental'
            else fetch_inbox_emails_single(email_addr, pwd, fetch_n=int(fetch_n))
        )
        
        # Merge Data
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
    fetch_n = st.number_input("Fetch last N emails", min_value=1, value=10, step=1)
    if st.button("📥 Fetch Last N Emails"):
        if process_fetch('last_n', fetch_n): st.success(f"Fetched last {fetch_n} emails.")
        else: st.warning("No valid credentials found in table.")

with colC:
    if st.button("🗑️ Clear All Stored Data"):
        st.session_state.mailbox_data = {} # Wipe fetched data
        st.success("Cleared all fetched emails (credentials preserved).")
        st.rerun()

# ---------- Email Counts ----------
st.markdown("### 📊 Email Counts per Account")
if not st.session_state.mailbox_data:
    st.write("No data fetched yet.")
else:
    # Create dynamic columns for metrics
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

# ---------- Email Presence Table (Dynamic) ----------
# 1. Identify all unique emails (Subject+From+Domain+Auth) across ALL accounts
all_keys = set()
email_presence_map = {} # { email_address: set(message_keys) }
new_email_keys = set()

# Only look at emails currently in the credentials list to keep table clean
valid_emails = [r["Email"] for i, r in st.session_state.creds_df.iterrows() if r["Email"] in st.session_state.mailbox_data]

for email_addr in valid_emails:
    df_acc = st.session_state.mailbox_data[email_addr]["df"]
    keys = set()
    for _, row in df_acc.iterrows():
        # Define what makes a message unique (excluding UID which differs per inbox)
        msg_key = (row["Domain"], row["Subject"], row["From"], row["SPF"], row["DKIM"], row["DMARC"])
        keys.add(msg_key)
        if row.get("is_new", False):
            new_email_keys.add(msg_key)
    email_presence_map[email_addr] = keys
    all_keys.update(keys)

# 2. Build the rows
rows = []
if all_keys:
    sorted_keys = sorted(list(all_keys), key=lambda k: (k not in new_email_keys, k[0], k[1])) # Sort by New, then Domain

    for (domain, subject, from_val, spf, dkim, dmarc) in sorted_keys:
        row_data = {
            "Domain": domain, "From": from_val, "Subject": subject,
            "Auth": "Pass" if all(res == 'pass' for res in [spf, dkim, dmarc]) else "Fail",
            "is_new": (domain, subject, from_val, spf, dkim, dmarc) in new_email_keys
        }
        # Add a column for each valid email account
        for email_addr in valid_emails:
            is_present = (domain, subject, from_val, spf, dkim, dmarc) in email_presence_map[email_addr]
            # Short column header
            col_header = email_addr.split('@')[0]
            row_data[col_header] = "✅" if is_present else "❌"
            
        rows.append(row_data)

    st.subheader("📋 Email Presence Table (Newest on Top)")
    if rows:
        presence_df = pd.DataFrame(rows)
        st.dataframe(
            presence_df.style.apply(highlight_new_rows, axis=1), 
            hide_index=True, 
            column_config={"is_new": None}
        )
else:
    st.info("No emails found in the active accounts.")

# ---------- Combined Master Inbox ----------
st.markdown("---")
st.subheader("📬 Combined Master Inbox")
all_dfs = []
for email_addr in valid_emails:
    data = st.session_state.mailbox_data[email_addr]
    if not data['df'].empty:
        df_copy = data['df'].copy()
        df_copy['Source Account'] = email_addr
        all_dfs.append(df_copy)

if all_dfs:
    combined_df = pd.concat(all_dfs, ignore_index=True)
    combined_df['UID_int'] = pd.to_numeric(combined_df['UID'], errors='coerce')
    sorted_combined_df = combined_df.sort_values(by=["is_new", "UID_int"], ascending=[False, False])
    display_cols = ["Source Account", "Domain", "From", "Subject", "SPF", "DKIM", "DMARC", "is_new"]
    st.dataframe(
        sorted_combined_df[display_cols].style.apply(highlight_new_rows, axis=1),
        hide_index=True,
        column_config={"is_new": None}
    )
else:
    st.info("No emails fetched yet.")

# ---------- Individual Raw Data ----------
with st.expander("Show Individual Raw Messages"):
    for email_addr in valid_emails:
        data = st.session_state.mailbox_data[email_addr]
        st.markdown(f"**{email_addr}** — Stored: {len(data['df'])}")
        if not data["df"].empty:
            df_to_show = data["df"].copy()
            df_to_show['UID_int'] = pd.to_numeric(df_to_show['UID'], errors='coerce')
            sorted_df_to_show = df_to_show.sort_values(by=["is_new", "UID_int"], ascending=[False, False])
            st.dataframe(
                sorted_df_to_show.drop(columns=['UID_int']).style.apply(highlight_new_rows, axis=1),
                hide_index=True, 
                column_config={"is_new": None}
            )
