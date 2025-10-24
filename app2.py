import streamlit as st
import imaplib
import email
from email.header import decode_header
import datetime
import re
import pandas as pd
import pytz

# ---------- Page Setup ----------
st.set_page_config(page_title="Multi-Account Inbox Comparator", layout="wide")
st.title("📧 Multi-Account Inbox Comparator (Deliverability Enhanced)")

# ---------- Robust Session State Initialization ----------
if "num_accounts" not in st.session_state:
    st.session_state.num_accounts = 5

if "accounts" not in st.session_state:
    st.session_state.accounts = {}

default_account_structure = {
    "email": "", "pwd": "", "last_uid": None,
    "df": pd.DataFrame(columns=["UID", "Domain", "Subject", "From", "SPF", "DKIM", "DMARC", "is_new", "Folder"])
}

for i in range(1, st.session_state.num_accounts + 1):
    acc_key = f"acc{i}"
    if acc_key not in st.session_state.accounts or "last_uid" not in st.session_state.accounts[acc_key]:
        st.session_state.accounts[acc_key] = default_account_structure.copy()
        st.session_state.accounts[acc_key]["df"] = pd.DataFrame(
            columns=["UID", "Domain", "Subject", "From", "SPF", "DKIM", "DMARC", "is_new", "Folder"]
        )

# ---------- Utilities ----------
def decode_mime_words(s):
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

def fetch_inbox_emails_single(email_addr, password, last_uid=None, fetch_n=None):
    results = []
    new_last_uid = last_uid
    
    def fetch_emails_from_folder(folder_name, is_new_fetch):
        nonlocal new_last_uid
        folder_results = []
        try:
            imap.select(folder_name, readonly=True)
        except imaplib.IMAP4.error:
            st.warning(f"Could not access folder '{folder_name}' for {email_addr}. Skipping.")
            return []

        uids = []
        if is_new_fetch and last_uid and folder_name.lower() == 'inbox':
            try:
                criteria = f'(UID {int(last_uid)+1}:*)'
                status, data = imap.uid('search', None, criteria)
                if status == 'OK' and data and data[0]: uids = data[0].split()
            except Exception:
                pass
        elif fetch_n:
            status, data = imap.uid('search', None, 'ALL')
            if status == 'OK' and data and data[0]: uids = data[0].split()[-int(fetch_n):]
        else:
            ist = pytz.timezone('Asia/Kolkata')
            today_ist = datetime.datetime.now(ist).strftime("%d-%b-%Y")
            status, data = imap.uid('search', None, f'(SINCE "{today_ist}")')
            if status == 'OK' and data and data[0]: uids = data[0].split()
        
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
                
                folder_results.append({
                    "UID": uid_dec, "Domain": domain, "Subject": subject,
                    "From": from_header, "SPF": spf, "DKIM": dkim, "DMARC": dmarc,
                    "Folder": folder_name.upper().replace('"[GMAIL]/', '').replace('"', '')
                })
                
                if folder_name.lower() == 'inbox' and (new_last_uid is None or int(uid_dec) > int(new_last_uid)):
                    new_last_uid = uid_dec
        return folder_results

    try:
        email_addr, password = email_addr.strip(), password.strip()
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_addr, password)
        is_new_fetch = (last_uid is not None)
        results.extend(fetch_emails_from_folder('INBOX', is_new_fetch))
        results.extend(fetch_emails_from_folder('"[Gmail]/Spam"', is_new_fetch))
        imap.logout()
    except imaplib.IMAP4.error as e:
        st.error(f"IMAP error for {email_addr}: {e}")
    except Exception as e:
        st.error(f"Error fetching {email_addr}: {e}")
        
    return pd.DataFrame(results), new_last_uid

def highlight_new_rows(row):
    return ['background-color: #D4EDDA'] * len(row) if row.get("is_new", False) else [''] * len(row)

def highlight_auth_fail(row):
    styles = [''] * len(row)
    try:
        if row["Auth"] == "Fail":
            auth_index = row.index.get_loc("Auth")
            styles[auth_index] = 'background-color: #F8D7DA'
    except KeyError:
        pass
    return styles

# ---------- Account Controls ----------
header_col, control_col, _ = st.columns([0.6, 0.3, 0.1])
with header_col:
    st.markdown(f"### Enter {st.session_state.num_accounts} Gmail accounts (email + app password)")

def add_account():
    st.session_state.num_accounts += 1
    new_acc_key = f"acc{st.session_state.num_accounts}"
    st.session_state.accounts[new_acc_key] = default_account_structure.copy()
    st.session_state.accounts[new_acc_key]["df"] = pd.DataFrame(
        columns=["UID", "Domain", "Subject", "From", "SPF", "DKIM", "DMARC", "is_new", "Folder"]
    )

def remove_account():
    if st.session_state.num_accounts > 1:
        removed_key = f"acc{st.session_state.num_accounts}"
        if removed_key in st.session_state.accounts:
            del st.session_state.accounts[removed_key]
        st.session_state.num_accounts -= 1
    else:
        st.error("Cannot remove the last account.")

with control_col:
    add_col, rem_col = st.columns(2)
    if add_col.button("➕ ADD", use_container_width=True):
        add_account()
        st.rerun()
    if rem_col.button("➖ REMOVE", use_container_width=True):
        remove_account()
        st.rerun()

st.markdown("---")

# ---------- Account Inputs ----------
cols = st.columns(st.session_state.num_accounts)
for i, col in enumerate(cols, start=1):
    with col:
        acc_key = f"acc{i}"
        if acc_key not in st.session_state.accounts: 
             continue 
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
    any_run = False
    new_data_fetched = False

    for i in range(1, st.session_state.num_accounts + 1): 
        acc_key = f"acc{i}"
        if acc_key not in st.session_state.accounts: continue
            
        acct = st.session_state.accounts[acc_key]
        if not acct.get("email") or not acct.get("pwd"):
            if fetch_type != 'clear': st.warning(f"Account {i} missing credentials — skipping.")
            continue
            
        any_run = True
        df_new, new_uid = (
            fetch_inbox_emails_single(acct["email"], acct["pwd"], last_uid=acct.get("last_uid"))
            if fetch_type == 'incremental'
            else fetch_inbox_emails_single(acct["email"], acct["pwd"], fetch_n=int(fetch_n))
        )

        if not df_new.empty:
            new_data_fetched = True
            current_df = acct["df"].drop(columns=['is_new'], errors='ignore')
            df_new['is_new'] = True

            merged_df = current_df.merge(
                df_new,
                on=["UID", "Folder", "Domain", "Subject", "From", "SPF", "DKIM", "DMARC"],
                how='outer',
                suffixes=('_old', '_new'),
                indicator=True
            )

            # --- FIX: Once a UID is in INBOX, never mark it new again ---
            def determine_is_new(row):
                if row['_merge'] != 'right_only':
                    return False
                uid = row['UID']
                if 'Folder_new' in row and row['Folder_new'].upper() != 'INBOX':
                    if uid in current_df.loc[current_df['Folder'].str.upper() == 'INBOX', 'UID'].astype(str).values:
                        return False
                return True

            merged_df['is_new'] = merged_df.apply(determine_is_new, axis=1)
            merged_df = merged_df.drop(columns=['_merge'])
            acct["df"] = merged_df.drop_duplicates(subset=["UID", "Folder"], keep='last')

            try: 
                inbox_uids = acct["df"][acct["df"]["Folder"] == 'INBOX']["UID"].astype(int)
                if not inbox_uids.empty:
                    acct["last_uid"] = str(inbox_uids.max())
            except (ValueError, IndexError): 
                acct["last_uid"] = acct.get("last_uid")

    if new_data_fetched:
        st.success(f"Fetched {fetch_type} emails successfully.")
    elif any_run:
        st.info("No new emails found.")
    return any_run

with colA:
    if st.button("🔄 Fetch New Emails (incremental)"):
        process_fetch('incremental')
        
with colB:
    fetch_n = st.number_input("Fetch last N emails", min_value=1, value=10, step=1, key="fetch_n")
    if st.button("📥 Fetch Last N Emails"):
        process_fetch('last_n', fetch_n)
        
with colC:
    if st.button("🗑️ Clear All Stored Data"):
        for i in range(1, st.session_state.num_accounts + 1):
            acc_key = f"acc{i}"
            if acc_key in st.session_state.accounts:
                st.session_state.accounts[acc_key] = default_account_structure.copy()
                st.session_state.accounts[acc_key]["df"] = pd.DataFrame(
                    columns=["UID", "Domain", "Subject", "From", "SPF", "DKIM", "DMARC", "is_new", "Folder"]
                )
        st.success("Cleared all stored data."); st.rerun()

# ---------- Email Counts ----------
st.markdown("### 📊 Email Counts per Account (Total Fetched)")
count_cols = st.columns(st.session_state.num_accounts)
for i, col in enumerate(count_cols, start=1):
    acc_key = f"acc{i}"
    if acc_key not in st.session_state.accounts: continue
        
    acct = st.session_state.accounts[acc_key]
    acct_df, total_count = acct["df"], len(acct["df"])
    email_label = acct.get("email", f"Account {i}")
    email_label = email_label.split('@')[0] if '@' in email_label else email_label
    inbox_count = (acct_df['Folder'] == 'INBOX').sum()
    spam_count = (acct_df['Folder'] == 'SPAM').sum()
    col.metric(label=email_label, value=f"Total: {total_count}", delta=f"Inbox: {inbox_count} | Spam: {spam_count}")

st.markdown("---")

# ---------- Email Presence Table ----------
MISSING_ICON = "⚪"
SPAM_ICON = "🔴"
INBOX_ICON = "🟢"

header_col_presence, legend_col_presence = st.columns([0.7, 0.3])
with header_col_presence:
    st.subheader("📋 Email Presence Table (Newest on Top)")
with legend_col_presence:
    st.markdown(f"**Legend:** {MISSING_ICON} = Missing | {SPAM_ICON} = SPAM | {INBOX_ICON} = INBOX")

all_keys, account_keys, new_email_keys = set(), {}, set()
for i in range(1, st.session_state.num_accounts + 1):
    acc_key = f"acc{i}"
    if acc_key not in st.session_state.accounts: continue
        
    df_acc = st.session_state.accounts[acc_key]["df"]
    keys = set()
    for _, row in df_acc.iterrows():
        email_key = (row["Domain"], row["Subject"], row["From"], row["SPF"], row["DKIM"], row["DMARC"], row["Folder"])
        keys.add(email_key)
        if row.get("is_new", False): 
            new_email_keys.add(email_key)
    account_keys[acc_key] = keys
    all_keys.update(keys)

rows = []
aggregated_keys = set()
sorted_keys = sorted(list(all_keys), key=lambda k: (k not in new_email_keys, k[0], k[1]))
for (domain, subject, from_val, spf, dkim, dmarc, folder) in sorted_keys:
    display_key = (domain, subject, from_val, spf, dkim, dmarc)
    if display_key in aggregated_keys:
        continue 
    aggregated_keys.add(display_key)
    flags = []
    is_new_email = False
    for i in range(1, st.session_state.num_accounts + 1): 
        acc_key = f"acc{i}"
        if acc_key not in st.session_state.accounts: 
            flags.append("N/A")
            continue
        found_rows = st.session_state.accounts[acc_key]["df"]
        found_rows = found_rows[
            (found_rows["Domain"] == domain) & 
            (found_rows["Subject"] == subject) &
            (found_rows["From"] == from_val) & 
            (found_rows["SPF"] == spf) & 
            (found_rows["DKIM"] == dkim) & 
            (found_rows["DMARC"] == dmarc)
        ]
        if found_rows.empty:
            flags.append(MISSING_ICON)
        elif 'SPAM' in found_rows['Folder'].values:
            flags.append(SPAM_ICON)
        else:
            flags.append(INBOX_ICON)
        if found_rows["is_new"].any():
            is_new_email = True

    auth_status = "Fail" if not all(res == 'pass' for res in [spf, dkim, dmarc]) else "Pass"
    rows.append({
        "Domain": domain, "From": from_val, "Subject": subject,
        **{f"Mail{j}": flags[j-1] for j in range(1, st.session_state.num_accounts + 1)},
        "Auth": auth_status,
        "is_new": is_new_email
    })

if rows:
    col_config = {f"Mail{j}": st.column_config.Column(f"Mail{j}", width="small") 
                  for j in range(1, st.session_state.num_accounts + 1)}
    col_config["is_new"] = None
    styled_df = (
        pd.DataFrame(rows)
        .style
        .apply(highlight_new_rows, axis=1)
        .apply(highlight_auth_fail, axis=1)
    )
    st.dataframe(styled_df, hide_index=True, column_config=col_config)
else:
    st.info("No emails fetched for the Presence Table yet.")

# ---------- Individual Raw Data ----------
st.markdown("---")
with st.expander("Show Individual Raw Data (Newest on Top)"):
    for i in range(1, st.session_state.num_accounts + 1):
        acc_key = f"acc{i}"
        if acc_key not in st.session_state.accounts: continue
        acct = st.session_state.accounts[acc_key]
        st.markdown(f"**Account {i}: {acct.get('email', 'N/A')}** — Stored: {len(acct['df'])}")
        if not acct["df"].empty:
            df_to_show = acct["df"].copy()
            df_to_show['UID_int'] = pd.to_numeric(df_to_show['UID'], errors='coerce')
            sorted_df_to_show = df_to_show.sort_values(by=["is_new", "UID_int"], ascending=[False, False])
            st.dataframe(
                sorted_df_to_show.drop(columns=['UID_int']).style.apply(highlight_new_rows, axis=1),
                hide_index=True,
                column_config={"is_new": None}
            )
