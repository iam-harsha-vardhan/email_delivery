import streamlit as st
import imaplib
import email
from email.header import decode_header
import datetime
import re
import pandas as pd
import pytz
# base64 is handled by email.message, no explicit import needed

# ---------- Page Setup ----------
st.set_page_config(page_title="Multi-Account Inbox Comparator", layout="wide")
st.title("📧 Multi-Account Inbox Comparator (5 accounts)")

# ---------- Robust Session State Initialization ----------
if "accounts" not in st.session_state:
    st.session_state.accounts = {}

# --- CHANGED: Added "Body" to the columns ---
DF_COLUMNS = ["UID", "Type", "Domain", "Subject", "From", "Body", "SPF", "DKIM", "DMARC", "is_new"]

default_account_structure = {
    "email": "", "pwd": "", "last_uid": None,
    "df": pd.DataFrame(columns=DF_COLUMNS)
}

for i in range(1, 6):
    acc_key = f"acc{i}"
    if acc_key not in st.session_state.accounts or "last_uid" not in st.session_state.accounts[acc_key]:
        st.session_state.accounts[acc_key] = default_account_structure.copy()
        st.session_state.accounts[acc_key]["df"] = pd.DataFrame(columns=DF_COLUMNS)

# ---------- Utilities ----------
def decode_mime_words(s):
    """Robust decoder for email headers, handles unknown-8bit safely."""
    if not s:
        return ""
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

# ---------- NEW: Function to get decoded email body ----------
def get_email_body(msg):
    """
    Finds the 'text/plain' part of an email and decodes it.
    Handles Base64 and quoted-printable automatically.
    """
    body = ""
    if msg.is_multipart():
        # Walk through all parts of the multipart message
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))

            # Look for the 'text/plain' part
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                try:
                    # get_payload(decode=True) handles Base64/quoted-printable
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    body = payload.decode(charset, errors="ignore")
                    break # Found the plain text body, stop looking
                except Exception:
                    continue
    else:
        # Not a multipart message, just get the payload
        ctype = msg.get_content_type()
        if ctype == 'text/plain':
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or 'utf-8'
                body = payload.decode(charset, errors="ignore")
            except Exception:
                body = "[Could not decode body]"
    
    return body.strip()

def extract_domain_from_address(address):
    if not address:
        return "-"
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

# --- CHANGED: Function now also checks the email body ---
def determine_email_type(subject, from_header, body):
    """
    Checks the (already decoded) subject, from headers, and body
    for keywords to assign a type.
    """
    # Combine subject, from, and body for searching
    search_string = (subject + " " + from_header + " " + body).lower()
    
    if "grm" in search_string:
        return "FPR"
    if "agm" in search_string:
        return "AJ"
    if "ajtc" in search_string:
        return "AJTC"
    
    return "-" # Default value if none are found

def fetch_inbox_emails_single(email_addr, password, last_uid=None, fetch_n=None):
    results = []
    new_last_uid = last_uid
    try:
        email_addr, password = email_addr.strip(), password.strip()
        if any(c in email_addr or c in password for c in [' ', '\n']):
            st.warning(f"⚠️ Credentials for {email_addr} may contain hidden spaces/newlines.")

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
                uids = data[0].split()[-int(fetch_n):]
        else:
            ist = pytz.timezone('Asia/Kolkata')
            today_ist = datetime.datetime.now(ist).strftime("%d-%b-%Y")
            status, data = imap.uid('search', None, f'(SINCE "{today_ist}")')
            if status == 'OK' and data and data[0]: 
                uids = data[0].split()

        for uid in uids:
            if not uid: 
                continue
            uid_dec = uid.decode()
            
            # --- CHANGED: Fetch full body, not just header ---
            res, msg_data = imap.uid('fetch', uid_dec, '(BODY.PEEK[])')
            
            if res == 'OK' and isinstance(msg_data[0], tuple):
                msg = email.message_from_bytes(msg_data[0][1])
                
                # Decode headers
                subject = decode_mime_words(msg.get("Subject", "No Subject"))
                from_header = decode_mime_words(msg.get("From", "-"))
                
                # --- ADDED: Decode the body ---
                body = get_email_body(msg)
                # Create a clean snippet for display
                body_snippet = " ".join(body.split()).strip()[:75] + '...' if body else "-"
                
                domain = extract_domain_from_address(from_header)
                spf, dkim, dmarc = extract_auth_results_from_headers(msg)
                
                # --- CHANGED: Determine type from decoded headers AND body ---
                email_type = determine_email_type(subject, from_header, body)
                
                results.append({
                    "UID": uid_dec, 
                    "Type": email_type,
                    "Domain": domain, 
                    "Subject": subject,
                    "From": from_header, 
                    "Body": body_snippet, # <-- Added new Body snippet
                    "SPF": spf, "DKIM": dkim, "DMARC": dmarc
                })
                if new_last_uid is None or int(uid_dec) > int(new_last_uid):
                    new_last_uid = uid_dec
        imap.logout()
    except imaplib.IMAP4.error as e: 
        st.error(f"IMAP error for {email_addr}: {e}")
    except Exception as e: 
        st.error(f"Error fetching {email_addr}: {e}")
    return pd.DataFrame(results), new_last_uid

def highlight_new_rows(row):
    return ['background-color: #90EE90'] * len(row) if row.get("is_new", False) else [''] * len(row)

# ---------- Account Input UI ----------
st.markdown("### Enter 5 Gmail accounts (email + app password)")
cols = st.columns(5)
for i, col in enumerate(cols, start=1):
    with col:
        acc_key = f"acc{i}"
        st.session_state.accounts[acc_key]["email"] = st.text_input(
            f"Account {i} Email", value=st.session_state.accounts[acc_key]["email"], key=f"email{i}"
        )
        st.session_state.accounts[acc_key]["pwd"] = st.text_input(
            f"Password {i}", value=st.session_state.accounts[acc_key]["pwd"], type="password", key=f"pwd{i}"
        )

# ---------- Fetch Controls ----------
st.markdown("---")
colA, colB, colC = st.columns([1, 1, 1])

def process_fetch(fetch_type, fetch_n=None):
    for i in range(1, 6):
        if "is_new" in st.session_state.accounts[f"acc{i}"]["df"].columns:
            st.session_state.accounts[f"acc{i}"]["df"]["is_new"] = False
    any_run = False
    for i in range(1, 6):
        acct = st.session_state.accounts[f"acc{i}"]
        if not acct.get("email") or not acct.get("pwd"):
            if fetch_type != 'clear': 
                st.warning(f"Account {i} missing credentials — skipping.")
            continue
        any_run = True
        df_new, new_uid = (
            fetch_inbox_emails_single(acct["email"], acct["pwd"], last_uid=acct.get("last_uid"))
            if fetch_type == 'incremental'
            else fetch_inbox_emails_single(acct["email"], acct["pwd"], fetch_n=int(fetch_n))
        )
        if not df_new.empty:
            df_new["is_new"] = True
            # Ensure new df has all columns from the main df, filling missing with '-'
            for col in DF_COLUMNS:
                if col not in df_new.columns:
                    df_new[col] = '-'
            
            acct["df"] = pd.concat([acct["df"], df_new], ignore_index=True).drop_duplicates(subset=["UID"], keep='last')
            try: 
                acct["last_uid"] = str(acct["df"]["UID"].astype(int).max())
            except (ValueError, IndexError): 
                acct["last_uid"] = acct.get("last_uid")
    return any_run

with colA:
    if st.button("🔄 Fetch New Emails (incremental)"):
        if process_fetch('incremental'): 
            st.success("Fetched incremental emails.")
with colB:
    fetch_n = st.number_input("Fetch last N emails", min_value=1, value=10, step=1)
    if st.button("📥 Fetch Last N Emails"):
        if process_fetch('last_n', fetch_n): 
            st.success(f"Fetched last {fetch_n} emails.")
with colC:
    if st.button("🗑️ Clear All Stored Data"):
        for i in range(1, 6):
            st.session_state.accounts[f"acc{i}"] = default_account_structure.copy()
            st.session_state.accounts[f"acc{i}"]["df"] = pd.DataFrame(columns=DF_COLUMNS)
        st.success("Cleared all stored data."); st.rerun()

# ---------- Email Counts ----------
st.markdown("### 📊 Email Counts per Account (Total Fetched)")
count_cols = st.columns(5)
for i, col in enumerate(count_cols, start=1):
    acct = st.session_state.accounts[f"acc{i}"]
    acct_df, total_count = acct["df"], len(acct["df"])
    new_count = acct_df["is_new"].sum() if "is_new" in acct_df.columns else 0
    email_label = acct.get("email", f"Account {i}")
    email_label = email_label.split('@')[0] if '@' in email_label else email_label
    col.metric(label=email_label, value=total_count, delta=f"{new_count} New" if new_count > 0 else None)

st.markdown("---")

# ---------- Email Presence Table ----------
# Note: Body snippet is NOT used as part of the key
all_keys, account_keys, new_email_keys = set(), {}, set()
for i in range(1, 6):
    df_acc = st.session_state.accounts[f"acc{i}"]["df"]
    keys = set()
    for _, row in df_acc.iterrows():
        # Body is not included in the key as it's not a stable identifier
        email_key = (row["Type"], row["Domain"], row["Subject"], row["From"], row["SPF"], row["DKIM"], row["DMARC"])
        keys.add(email_key)
        if row.get("is_new", False): 
            new_email_keys.add(email_key)
    account_keys[f"acc{i}"] = keys
    all_keys.update(keys)

rows = []
sorted_keys = sorted(list(all_keys), key=lambda k: (k not in new_email_keys, k[0], k[1], k[2]))

for (email_type, domain, subject, from_val, spf, dkim, dmarc) in sorted_keys:
    flags = ["✅" if (email_type, domain, subject, from_val, spf, dkim, dmarc) in account_keys[f"acc{i}"] else "❌" for i in range(1, 6)]
    auth_status = "Pass" if all(res == 'pass' for res in [spf, dkim, dmarc]) else "Fail"
    rows.append({
        "Type": email_type,
        "Domain": domain, 
        "From": from_val, 
        "Subject": subject,
        "Mail1": flags[0], "Mail2": flags[1], "Mail3": flags[2],
        "Mail4": flags[3], "Mail5": flags[4], "Auth": auth_status,
        "is_new": (email_type, domain, subject, from_val, spf, dkim, dmarc) in new_email_keys
    })

if rows:
    st.subheader("📋 Email Presence Table (Newest on Top)")
    st.dataframe(pd.DataFrame(rows).style.apply(highlight_new_rows, axis=1), hide_index=True, column_config={"is_new": None})
else:
    st.info("No emails fetched for the Presence Table yet.")

# ---------- Combined Master Inbox ----------
st.markdown("---")
st.subheader("📬 Combined Master Inbox (All Accounts)")
all_dfs = []
for i in range(1, 6):
    acct = st.session_state.accounts[f"acc{i}"]
    if not acct['df'].empty and acct.get('email'):
        df_copy = acct['df'].copy()
        df_copy['Source Account'] = acct['email']
        all_dfs.append(df_copy)

if all_dfs:
    combined_df = pd.concat(all_dfs, ignore_index=True)
    combined_df['UID_int'] = pd.to_numeric(combined_df['UID'], errors='coerce')
    sorted_combined_df = combined_df.sort_values(by=["is_new", "UID_int"], ascending=[False, False])
    
    # --- CHANGED: Added "Body" to the display columns ---
    display_cols = ["Source Account", "Type", "Domain", "From", "Subject", "Body", "SPF", "DKIM", "DMARC", "is_new"]
    
    st.dataframe(
        sorted_combined_df[display_cols].style.apply(highlight_new_rows, axis=1),
        hide_index=True,
        column_config={"is_new": None}
    )
else:
    st.info("No emails fetched to display in the master inbox. Enter credentials and fetch emails above.")

# ---------- Individual Raw Data ----------
with st.expander("Show Individual Raw Messages (Newest on Top)"):
    for i in range(1, 6):
        acct = st.session_state.accounts[f'acc{i}']
        st.markdown(f"**Account {i}: {acct.get('email', 'N/A')}** — Stored: {len(acct['df'])}")
        if not acct["df"].empty:
            df_to_show = acct["df"].copy()
            df_to_show['UID_int'] = pd.to_numeric(df_to_show['UID'], errors='coerce')
            sorted_df_to_show = df_to_show.sort_values(by=["is_new", "UID_int"], ascending=[False, False])
            
            # --- CHANGED: "Body" will now be included in the raw display ---
            display_cols_raw = [col for col in DF_COLUMNS if col in sorted_df_to_show.columns and col != 'UID_int' and col != 'UID']
            
            st.dataframe(
                sorted_df_to_show[display_cols_raw].style.apply(highlight_new_rows, axis=1),
                hide_index=True,
                column_config={"is_new": None}
            )
