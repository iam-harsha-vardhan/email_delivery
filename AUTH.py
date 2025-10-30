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

# Define the columns that must exist in the DataFrame
DF_COLS = ["Subject", "Date", "SPF", "DKIM", "DMARC", "Domain", "Type", "Sub ID", "Message-ID", "Mailbox", "New_Fetch"]

# --- Session state setup ---
if 'df' not in st.session_state:
    # Initialize df with all required columns, including New_Fetch, to prevent KeyError
    st.session_state.df = pd.DataFrame(columns=DF_COLS)
if 'last_uid' not in st.session_state:
    st.session_state.last_uid = None
if 'spam_df' not in st.session_state:
    # Initialize spam_df with all required columns
    st.session_state.spam_df = pd.DataFrame(columns=DF_COLS)
if 'email_input' not in st.session_state:
    st.session_state.email_input = ""
if 'password_input' not in st.session_state:
    st.session_state.password_input = ""
if 'fetch_dates' not in st.session_state:
    today = datetime.date.today()
    yesterday = today - datetime.timedelta(days=1)
    # Initialize with a date range (yesterday to today)
    st.session_state.fetch_dates = (yesterday, today)


# --- Email + Password + Date Selection Row ---
with st.container():
    col1, col2, col3, col4 = st.columns([3, 3, 2, 1])

    with col1:
        email_input = st.text_input("📧 Gmail Address", key="email_box")

    with col2:
        password_input = st.text_input("🔐 App Password", type="password", key="pwd_box")
    
    with col3:
        # st.date_input for date range selection
        date_range = st.date_input(
            "Select Date Range", 
            value=st.session_state.fetch_dates, 
            max_value=datetime.date.today(),
            key="date_box",
            help="Select the start and end dates for fetching emails (up to 2 dates)."
        )
        # Handle single date vs date range output from widget
        if isinstance(date_range, tuple) and len(date_range) == 2:
            st.session_state.fetch_dates = date_range
        elif isinstance(date_range, datetime.date):
            st.session_state.fetch_dates = (date_range, date_range)
        # Ensure start is before or equal to end
        if len(st.session_state.fetch_dates) == 2 and st.session_state.fetch_dates[0] > st.session_state.fetch_dates[1]:
             st.session_state.fetch_dates = (st.session_state.fetch_dates[1], st.session_state.fetch_dates[0])


    with col4:
        st.markdown("####")  # spacing alignment
        if st.button("🔁", help="Clear all data and credentials"):
            for key in list(st.session_state.keys()):
                if key not in ['date_box', 'fetch_dates']: # Preserve date input state
                    del st.session_state[key]
            st.rerun()

# --- Store credentials in session state for reruns ---
st.session_state.email_input = email_input
st.session_state.password_input = password_input

# --- Validation ---
if not st.session_state.email_input or not st.session_state.password_input:
    st.warning("Please enter both your Gmail address and an App Password to continue.")
    st.stop()
if len(st.session_state.fetch_dates) != 2:
    st.warning("Please select a valid date range (or a single date).")
    st.stop()
    
# Get dates
START_DATE = st.session_state.fetch_dates[0]
END_DATE = st.session_state.fetch_dates[1]


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
        "SPF": "-", "DKIM": "-", "DMARC": "-", "Domain": "-", 
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


def fetch_emails(start_date, end_date, mailbox="inbox"):
    """Fetch emails from a given mailbox based on date range (inclusive of start/end dates)."""
    results = []
    
    # Format dates for IMAP
    start_date_str = start_date.strftime("%d-%b-%Y")
    # IMAP SEARCH command needs a "BEFORE" date that is *the day after* the required end date
    day_after_end = end_date + datetime.timedelta(days=1)
    day_after_end_str = day_after_end.strftime("%d-%b-%Y")
    
    new_last_uid = None 
    
    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(st.session_state.email_input, st.session_state.password_input)
        imap.select(mailbox)

        # IMAP criteria for date range
        criteria = f'(SINCE {start_date_str} BEFORE {day_after_end_str})'
        
        # Always fetch headers by UID for sorting/deduping
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
            
            # Track the highest UID found for potential future use.
            if mailbox == "inbox":
                 new_last_uid = max(new_last_uid, uid_decoded) if new_last_uid else uid_decoded

        imap.logout()
    except imaplib.IMAP4.error as e:
        if "AUTHENTICATIONFAILED" in str(e).upper():
             st.error("❌ Login Failed! Please check your **Gmail Address** and **App Password**.")
        else:
             st.error(f"❌ IMAP Error fetching from {mailbox}: {str(e)}")
    except Exception as e:
        st.error(f"❌ General Error fetching from {mailbox}: {str(e)}")
        
    return pd.DataFrame(results, columns=DF_COLS), new_last_uid


def fetch_all_emails(start_date, end_date):
    """Fetch from Inbox and Spam together, avoiding duplicates."""
    
    # Fetch data for the specified date range
    inbox_df, new_uid = fetch_emails(start_date, end_date, "inbox")
    spam_df, _ = fetch_emails(start_date, end_date, "[Gmail]/Spam") 

    combined_df = pd.concat([inbox_df, spam_df], ignore_index=True)

    # Prepare existing data for merge: Mark all existing rows as 'old'
    if not st.session_state.df.empty:
        # Safely assign 'False' to New_Fetch for old data
        st.session_state.df.loc[:, "New_Fetch"] = False 
        
        # Drop duplicates from the new fetch based on Message-ID
        seen_ids = set(st.session_state.df["Message-ID"].dropna())
        combined_df = combined_df[~combined_df["Message-ID"].isin(seen_ids)].copy()

    return combined_df, new_uid

# --- Styling Functions ---

def highlight_failed_auth(row):
    """Applies a light red background to rows where SPF, DKIM, or DMARC is not 'pass'."""
    # Ensure columns exist before checking them 
    spf_status = row.get('SPF', '')
    dkim_status = row.get('DKIM', '')
    dmarc_status = row.get('DMARC', '')

    failed = (spf_status != 'pass') or \
             (dkim_status != 'pass') or \
             (dmarc_status != 'pass')
    
    style = 'background-color: rgba(255, 0, 0, 0.2)' # Light red
    return [style] * len(row) if failed else [''] * len(row)


def highlight_main_table(row):
    """
    Applies styling for both New Fetch (Light Blue) and Failed Auth (Light Red, prioritized).
    """
    # 1. Check for Failed Authentication (Highest Priority)
    spf_status = row.get('SPF', '')
    dkim_status = row.get('DKIM', '')
    dmarc_status = row.get('DMARC', '')

    failed = (spf_status != 'pass') or \
             (dkim_status != 'pass') or \
             (dmarc_status != 'pass')

    if failed:
        style = 'background-color: rgba(255, 0, 0, 0.2)' # Light Red
        return [style] * len(row)

    # 2. Check for New Fetch (Lower Priority)
    is_new = row.get('New_Fetch', False) 
    if is_new:
        style = 'background-color: rgba(0, 150, 255, 0.1)' # Light Blue
        return [style] * len(row)

    # 3. Default (No Highlight)
    return [''] * len(row)


# --- Action Buttons ---
colA, colB = st.columns([1.5, 2])

with colA:
    date_range_label = f" ({START_DATE} to {END_DATE})"
    if st.button(f"📥 Fetch Date Range {date_range_label}", help="Fetches ALL emails from Inbox and Spam within the selected date range and adds new unique emails to the table."):
        
        # Reset new fetch markers on old data
        if not st.session_state.df.empty:
             st.session_state.df.loc[:, "New_Fetch"] = False

        with st.spinner(f"Fetching emails for date range {date_range_label} (Inbox + Spam)..."):
            
            df_new, new_uid = fetch_all_emails(START_DATE, END_DATE)
            
            if not df_new.empty:
                # Concatenate new data to old data
                st.session_state.df = pd.concat([df_new, st.session_state.df], ignore_index=True)
                
                # Sort to put the new fetch data (New_Fetch=True) at the top
                st.session_state.df = st.session_state.df.sort_values(
                    by='New_Fetch', 
                    ascending=False, 
                    ignore_index=True
                )
                
                if new_uid:
                    st.session_state.last_uid = new_uid

                st.success(f"✅ Fetched and added {len(df_new)} new unique emails for {date_range_label}.")
            else:
                st.info(f"No new unique emails found for the date range {date_range_label}.")

with colB:
    spam_label = f" ({START_DATE} to {END_DATE})"
    if st.button(f"🗑️ Fetch Spam Folder {spam_label}", help="Fetches all unique spam emails within the selected date range."):
         
         # Reset new fetch markers on old spam data
         if not st.session_state.spam_df.empty:
             st.session_state.spam_df.loc[:, "New_Fetch"] = False

         with st.spinner(f"Fetching spam folder for {spam_label}..."):
            spam_df_new, _ = fetch_emails(START_DATE, END_DATE, "[Gmail]/Spam")
            
            if not st.session_state.spam_df.empty:
                seen_ids = set(st.session_state.spam_df["Message-ID"].dropna())
                spam_df_new = spam_df_new[~spam_df_new["Message-ID"].isin(seen_ids)].copy()
            
            if not spam_df_new.empty:
                st.session_state.spam_df = pd.concat([spam_df_new, st.session_state.spam_df], ignore_index=True)
                st.session_state.spam_df = st.session_state.spam_df.sort_values(
                    by='New_Fetch', 
                    ascending=False, 
                    ignore_index=True
                )
                st.success(f"✅ Added {len(spam_df_new)} unique spam emails for {spam_label}.")
            else:
                st.info(f"No new unique spam emails found for {spam_label}.")

# --- Inbox + Spam Display ---
st.subheader("📬 Processed Emails")
inbox_cols = ["Subject", "Date", "Domain", "SPF", "DKIM", "DMARC", "Type", "Mailbox"] 

if not st.session_state.df.empty:
    display_df = st.session_state.df.reindex(columns=inbox_cols, fill_value="-")
    
    # *** APPLY THE NEW COMBINED STYLING HERE ***
    styled_display_df = display_df.style.apply(highlight_main_table, axis=1)
    
    st.dataframe(styled_display_df, use_container_width=True)
else:
    st.info(f"No email data yet. Select a date range and click 'Fetch Date Range'.")

# --- Failed Auth Display (Styled with Red Background) ---
if not st.session_state.df.empty:
    failed_df = st.session_state.df[
        (st.session_state.df["SPF"] != "pass") |
        (st.session_state.df["DKIM"] != "pass") |
        (st.session_state.df["DMARC"] != "pass")
    ]

    if not failed_df.empty:
        st.subheader("❌ Failed Auth Emails (Redundant Table, Still Highlighted Red)")
        failed_cols = ["Subject", "Domain", "SPF", "DKIM", "DMARC", "Type", "Sub ID", "Mailbox"]
        
        # Still apply the red styling for consistency and readability here
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
    
    # Apply the combined styling (since spam could also potentially fail auth, though less relevant)
    styled_spam_df = display_spam_df.style.apply(
        highlight_main_table, 
        axis=1
    )
    
    st.dataframe(styled_spam_df, use_container_width=True)
