import streamlit as st
import imaplib
import email
from email.header import decode_header
import datetime
import re
import pandas as pd
import base64

# --- Page Setup ---
st.set_page_config(page_title="Email Auth Checker", layout="wide")
st.title("📧 Email Authentication Report (SPF/DKIM/DMARC)")

# --- Session state setup ---
if 'df' not in st.session_state:
    st.session_state.df = pd.DataFrame()
if 'last_uid' not in st.session_state:
    st.session_state.last_uid = None
if 'spam_df' not in st.session_state:
    st.session_state.spam_df = pd.DataFrame()
if 'email_input' not in st.session_state:
    st.session_state.email_input = ""
if 'password_input' not in st.session_state:
    st.session_state.password_input = ""
if 'fetch_start_date' not in st.session_state:
    # Initialize with yesterday as a safe default
    st.session_state.fetch_start_date = datetime.date.today() - datetime.timedelta(days=1)

# --- Email + Password + Date Selection Row ---
with st.container():
    col1, col2, col3, col4 = st.columns([3, 3, 2, 1])

    with col1:
        email_input = st.text_input("📧 Gmail Address", key="email_box")

    with col2:
        password_input = st.text_input("🔐 App Password", type="password", key="pwd_box")
    
    with col3:
        # st.date_input to select the starting date for the fetch
        selected_date = st.date_input(
            "Start Date for Fetch", 
            value=st.session_state.fetch_start_date, 
            max_value=datetime.date.today(),
            key="date_box",
            help="Select the starting date for fetching emails."
        )
        # Update session state
        st.session_state.fetch_start_date = selected_date

    with col4:
        st.markdown("####")  # spacing alignment
        if st.button("🔁", help="Clear all data and credentials"):
            for key in list(st.session_state.keys()):
                if key not in ['date_box', 'fetch_start_date']: # Preserve date input state
                    del st.session_state[key]
            st.rerun()

# --- Store credentials in session state for reruns ---
st.session_state.email_input = email_input
st.session_state.password_input = password_input

# --- Validation ---
if not st.session_state.email_input or not st.session_state.password_input:
    st.warning("Please enter both your Gmail address and an App Password to continue.")
    st.stop()

# --- Utility Functions ---

def decode_mime_words(s):
    """Decode MIME encoded words safely."""
    decoded_string = ""
    if not s:
        return decoded_string
    for part, encoding in decode_header(s):
        try:
            if isinstance(part, bytes):
                decoded_string += part.decode(encoding or 'utf-8', errors='ignore')
            else:
                decoded_string += part
        except (LookupError, TypeError):
            if isinstance(part, bytes):
                decoded_string += part.decode('utf-8', errors='ignore')
            else:
                decoded_string += str(part)
    return decoded_string.strip()

def extract_id_details(search_string, data):
    """Finds the *first* matching Sub ID pattern and sets the Type."""
    sub_id_match = re.search(
        r'(GTC-[^@_]+|GMFP-[^@_]+|GRM-[^@_]+)', 
        search_string, 
        re.I
    )

    if sub_id_match:
        matched_id_string = sub_id_match.group(1)
        data["Sub ID"] = matched_id_string
        id_lower = matched_id_string.lower()
        
        if 'grm' in id_lower:
            data["Type"] = 'FPR'
        elif 'gmfp' in id_lower:
            data["Type"] = 'FP'
        elif 'gtc' in id_lower:
            data["Type"] = 'FPTC'
        
        return True
    return False

def parse_email_message(msg):
    """Extracts all relevant details from an email message object."""
    
    data = {
        "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
        "Date": msg.get("Date", "No Date"),
        "SPF": "-", "DKIM": "-", "DMARC": "-", "Domain": "-", # Removed "DMARC Policy"
        "Type": "-", "Sub ID": "-", "Message-ID": decode_mime_words(msg.get("Message-ID", "")),
        "New_Fetch": True # Default to True
    }

    # --- Standard Header Parsing (SPF, DKIM, Domain) ---
    headers_str = ''.join(f"{header}: {value}\n" for header, value in msg.items())
    
    match_auth = re.search(r'Authentication-Results:.*?smtp.mailfrom=([\w\.-]+)', headers_str, re.I)
    if match_auth:
        data["Domain"] = match_auth.group(1).lower()
    else:
        # Fallback: Extract from the 'From' header using robust regex
        from_header = decode_mime_words(msg.get('From', ''))
        match = re.search(r'<(?:.+@)?([\w\.-]+)>|@([\w\.-]+)$', from_header)
        if match:
            domain = match.group(1) if match.group(1) else match.group(2)
            if domain:
                data["Domain"] = domain.lower()

    spf_match = re.search(r'spf=(\w+)', headers_str, re.I)
    dkim_match = re.search(r'dkim=(\w+)', headers_str, re.I)
    dmarc_match = re.search(r'dmarc=(\w+)', headers_str, re.I)
    
    if spf_match: data["SPF"] = spf_match.group(1).lower()
    if dkim_match: data["DKIM"] = dkim_match.group(1).lower()
    if dmarc_match: data["DMARC"] = dmarc_match.group(1).lower()

    # --- ID Extraction Logic (Unchanged) ---
    found_plain_id = extract_id_details(headers_str, data)
    if not found_plain_id:
        for header_name, header_value in msg.items():
            if not header_value: continue
            parts = str(header_value).split('_')
            for part in parts:
                if len(part) < 20: continue
                try:
                    padded_part = part + '=' * (-len(part) % 4)
                    decoded_bytes = base64.b64decode(padded_part)
                    decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
                    if extract_id_details(decoded_string, data):
                        break
                except Exception:
                    pass
            if data["Type"] != "-":
                break

    return data


def fetch_emails(start_date, last_uid=None, mailbox="inbox", use_uid_since=True):
    """Fetch emails from a given mailbox based on date or UID."""
    results = []
    new_last_uid = last_uid
    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(st.session_state.email_input, st.session_state.password_input)
        imap.select(mailbox)

        date_str = start_date.strftime("%d-%b-%Y")
        
        # Decide criteria based on mailbox and existing data
        if mailbox == "inbox" and last_uid and use_uid_since:
            # Incremental fetch for Inbox
            criteria = f'(UID {int(last_uid)+1}:* SINCE {date_str})'
        else:
            # Full fetch from selected date (used for initial Inbox fetch and all Spam fetches)
            criteria = f'(SINCE {date_str})'
        
        status, data = imap.uid('search', None, criteria)
        uids = data[0].split()

        for uid in uids:
            uid_decoded = uid.decode()
            _, msg_data = imap.uid('fetch', uid, '(BODY.PEEK[HEADER])')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    email_data = parse_email_message(msg)
                    email_data["Mailbox"] = "Inbox" if mailbox == "inbox" else "Spam"
                    email_data["New_Fetch"] = True # Mark as new
                    results.append(email_data)
            if mailbox == "inbox":
                new_last_uid = uid_decoded
        imap.logout()
    except imaplib.IMAP4.error as e:
        if "AUTHENTICATIONFAILED" in str(e).upper():
             st.error("❌ Login Failed! Please check your **Gmail Address** and **App Password**.")
        else:
             st.error(f"❌ IMAP Error fetching from {mailbox}: {str(e)}")
    except Exception as e:
        st.error(f"❌ General Error fetching from {mailbox}: {str(e)}")
        
    return pd.DataFrame(results), new_last_uid


def fetch_all_emails(start_date, last_uid=None, use_uid_since=True):
    """Fetch from Inbox and Spam together, avoiding duplicates."""
    inbox_df, new_uid = fetch_emails(start_date, last_uid, "inbox", use_uid_since)
    spam_df, _ = fetch_emails(start_date, None, "[Gmail]/Spam", use_uid_since=False) # Spam always does a full date fetch

    combined_df = pd.concat([inbox_df, spam_df], ignore_index=True)

    # Mark all existing rows as 'old' before combining them with the new data
    if not st.session_state.df.empty:
        st.session_state.df["New_Fetch"] = False
        seen_ids = set(st.session_state.df["Message-ID"].dropna())
        combined_df = combined_df[~combined_df["Message-ID"].isin(seen_ids)].copy()

    return combined_df, new_uid

# --- Styling Functions ---

def highlight_new_fetch(row):
    """Applies a distinct light blue background to rows from the current fetch."""
    style = 'background-color: rgba(0, 150, 255, 0.1)' # Light blue
    return [style] * len(row) if row['New_Fetch'] else [''] * len(row)

def highlight_failed_auth(row):
    """Applies a light red background to rows where SPF, DKIM, or DMARC is not 'pass'."""
    failed = (row['SPF'] != 'pass') or \
             (row['DKIM'] != 'pass') or \
             (row['DMARC'] != 'pass')
    
    style = 'background-color: rgba(255, 0, 0, 0.2)' # Light red
    return [style] * len(row) if failed else [''] * len(row)

# --- Action Buttons ---
colA, colB, colC = st.columns([1.5, 1.5, 2])

with colA:
    button_label = "🔄 Fetch New (Incremental)" if not st.session_state.df.empty else "📥 Fetch Initial Data"
    if st.button(button_label, help=f"Fetches new emails since last run or from {st.session_state.fetch_start_date}"):
        with st.spinner("Fetching emails (Inbox + Spam)..."):
            # Use UID and SINCE for incremental fetches if data exists
            use_uid = not st.session_state.df.empty
            
            df, new_uid = fetch_all_emails(st.session_state.fetch_start_date, st.session_state.last_uid, use_uid)
            
            if not df.empty:
                st.session_state.df = pd.concat([df, st.session_state.df], ignore_index=True)
                st.session_state.df = st.session_state.df.sort_values(
                    by='New_Fetch', 
                    ascending=False, 
                    ignore_index=True
                )
                st.session_state.last_uid = new_uid
                st.success(f"✅ Fetched {len(df)} new unique emails (Inbox + Spam).")
            else:
                st.info("No new unique emails found.")

with colB:
    # Button to re-fetch all data from the selected start date
    if st.button("🗓️ Re-Fetch from Date", help=f"Re-fetches ALL data from {st.session_state.fetch_start_date} and overwrites existing data."):
        if st.session_state.df.empty or st.checkbox(f"Confirm full re-fetch from **{st.session_state.fetch_start_date}**?", key="confirm_refetch"):
            # Reset existing data, but keep date
            st.session_state.df = pd.DataFrame()
            st.session_state.last_uid = None
            
            with st.spinner(f"Re-fetching ALL emails from {st.session_state.fetch_start_date} (Inbox + Spam)..."):
                # Always pass use_uid_since=False for a full re-fetch
                df, new_uid = fetch_all_emails(st.session_state.fetch_start_date, st.session_state.last_uid, use_uid_since=False)
                
                if not df.empty:
                    st.session_state.df = pd.concat([df, st.session_state.df], ignore_index=True)
                    st.session_state.df = st.session_state.df.sort_values(
                        by='New_Fetch', 
                        ascending=False, 
                        ignore_index=True
                    )
                    st.session_state.last_uid = new_uid
                    st.success(f"✅ Re-fetched and added {len(df)} unique emails (Inbox + Spam).")
                else:
                    st.info("No emails found for the selected date range.")
        else:
             st.info("Re-fetch cancelled.")

# --- Spam Folder Display Logic (Simplified and added styling) ---
with colC:
    if st.button("🗑️ Fetch Spam Folder", help=f"Fetches all unique spam emails SINCE {st.session_state.fetch_start_date}"):
         with st.spinner("Fetching spam folder..."):
            spam_df, _ = fetch_emails(st.session_state.fetch_start_date, None, "[Gmail]/Spam", use_uid_since=False)
            
            if not st.session_state.spam_df.empty:
                # Mark existing spam data as old and concatenate
                st.session_state.spam_df["New_Fetch"] = False
                seen_ids = set(st.session_state.spam_df["Message-ID"].dropna())
                spam_df = spam_df[~spam_df["Message-ID"].isin(seen_ids)].copy()
            
            if not spam_df.empty:
                st.session_state.spam_df = pd.concat([spam_df, st.session_state.spam_df], ignore_index=True)
                st.session_state.spam_df = st.session_state.spam_df.sort_values(
                    by='New_Fetch', 
                    ascending=False, 
                    ignore_index=True
                )
                st.success(f"✅ Added {len(spam_df)} unique spam emails.")
            else:
                st.info("No new unique spam emails found.")

# --- Inbox + Spam Display ---
st.subheader("📬 Processed Emails")
inbox_cols = ["Subject", "Date", "Domain", "SPF", "DKIM", "DMARC", "Type", "Mailbox"] # Removed "DMARC Policy"

if not st.session_state.df.empty:
    display_df = st.session_state.df.reindex(columns=inbox_cols, fill_value="-")
    
    # Apply the new fetch styling
    styled_display_df = display_df.style.apply(highlight_new_fetch, axis=1)
    
    st.dataframe(styled_display_df, use_container_width=True)
else:
    st.info(f"No email data yet. Use the buttons above to fetch emails starting from {st.session_state.fetch_start_date}.")

# --- Failed Auth Display (Styled with Red Background) ---
if not st.session_state.df.empty:
    # Filter only on the currently fetched data (which is sorted)
    failed_df = st.session_state.df[
        (st.session_state.df["SPF"] != "pass") |
        (st.session_state.df["DKIM"] != "pass") |
        (st.session_state.df["DMARC"] != "pass")
    ]

    if not failed_df.empty:
        st.subheader("❌ Failed Auth Emails")
        failed_cols = ["Subject", "Domain", "SPF", "DKIM", "DMARC", "Type", "Sub ID", "Mailbox"] # Removed "DMARC Policy"
        
        # Apply the red failure styling (new fetch background will be ignored here)
        styled_failed_df = failed_df[failed_cols].style.apply(
            highlight_failed_auth, 
            axis=1
        )
        
        st.dataframe(styled_failed_df, use_container_width=True)
    else:
        st.success("✅ All fetched emails passed SPF, DKIM, and DMARC.")

# --- Spam Folder Display (Styled with New Fetch Background) ---
if not st.session_state.spam_df.empty:
    st.subheader("🚫 Spam Folder Emails")
    spam_cols = ["Subject", "Date", "Domain", "Type", "Mailbox"]
    display_spam_df = st.session_state.spam_df.reindex(columns=spam_cols, fill_value="-")
    
    # Apply the new fetch styling
    styled_spam_df = display_spam_df.style.apply(
        highlight_new_fetch, 
        axis=1
    )
    
    st.dataframe(styled_spam_df, use_container_width=True)
