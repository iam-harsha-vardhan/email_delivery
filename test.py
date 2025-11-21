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

# Define the columns that must exist in the DataFrame (Added Batch_ID)
DF_COLS = ["Subject", "Date", "SPF", "DKIM", "DMARC", "Domain", "Type", "Sub ID", "Message-ID", "Mailbox", "Batch_ID"]

# --- Session state setup ---
if 'df' not in st.session_state:
    st.session_state.df = pd.DataFrame(columns=DF_COLS)
if 'last_uid' not in st.session_state:
    st.session_state.last_uid = None
if 'spam_df' not in st.session_state:
    st.session_state.spam_df = pd.DataFrame(columns=DF_COLS)
if 'email_input' not in st.session_state:
    st.session_state.email_input = ""
if 'password_input' not in st.session_state:
    st.session_state.password_input = ""
# New: Counter to generate unique ID for every button click
if 'batch_counter' not in st.session_state:
    st.session_state.batch_counter = 0

# --- Initialize or update dates to (Today, Today) if not set ---
today = datetime.date.today()
if 'fetch_dates' not in st.session_state or st.session_state.fetch_dates is None:
    st.session_state.fetch_dates = (today, today)


# --- Email + Password + Date Selection Row ---
with st.container():
    col1, col2, col3, col4 = st.columns([3, 3, 2, 1])

    with col1:
        email_input = st.text_input("📧 Gmail Address", key="email_box")

    with col2:
        password_input = st.text_input("🔐 App Password", type="password", key="pwd_box")
    
    with col3:
        date_range = st.date_input(
            "Select Date Range", 
            value=st.session_state.fetch_dates, 
            max_value=today,
            key="date_box",
            help="Select the start and end dates for fetching emails."
        )
        
        if isinstance(date_range, tuple) and len(date_range) == 2:
            start_date, end_date = date_range
            if start_date > end_date:
                start_date, end_date = end_date, start_date
            st.session_state.fetch_dates = (start_date, end_date)
        elif isinstance(date_range, datetime.date):
            st.session_state.fetch_dates = (date_range, date_range)
        elif date_range is None or len(date_range) == 0:
            st.session_state.fetch_dates = (today, today)

    with col4:
        st.markdown("####")
        if st.button("🔁", help="Clear all data and credentials"):
            for key in list(st.session_state.keys()):
                if key not in ['date_box', 'fetch_dates']:
                    del st.session_state[key]
            st.rerun()

# --- Store credentials ---
st.session_state.email_input = email_input
st.session_state.password_input = password_input

if not st.session_state.email_input or not st.session_state.password_input:
    st.warning("Please enter both your Gmail address and an App Password to continue.")
    st.stop()

START_DATE = st.session_state.fetch_dates[0]
END_DATE = st.session_state.fetch_dates[1]
IS_DEFAULT_TODAY = (START_DATE == today and END_DATE == today)
IS_SINGLE_DAY = (START_DATE == END_DATE)


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
    """
    Finds the matching Sub ID pattern and sets the Type.
    Updated to include GRTC -> FPRTC logic.
    """
    # Updated Regex to include GRTC
    sub_id_match = re.search(
        r'(GTC-[^@_]+|GMFP-[^@_]+|GRM-[^@_]+|GRTC-[^@_]+)', 
        search_string, 
        re.I
    )

    if sub_id_match:
        matched_id_string = sub_id_match.group(1)
        data["Sub ID"] = matched_id_string
        id_lower = matched_id_string.lower()
        
        # Updated Logic
        if 'grm' in id_lower:
            data["Type"] = 'FPR'
        elif 'gmfp' in id_lower:
            data["Type"] = 'FP'
        elif 'gtc' in id_lower:
            data["Type"] = 'FPTC'
        elif 'grtc' in id_lower: # New Condition
            data["Type"] = 'FPRTC'
        
        return True
    return False

def parse_email_message(msg):
    """Extracts all relevant details from an email message object."""
    
    data = {
        "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
        "Date": msg.get("Date", "No Date"),
        "SPF": "-", "DKIM": "-", "DMARC": "-", "Domain": "-", 
        "Type": "-", "Sub ID": "-", "Message-ID": decode_mime_words(msg.get("Message-ID", "")),
        "Batch_ID": 0 # Placeholder, will be updated on fetch
    }

    # --- Standard Header Parsing ---
    headers_str = ''.join(f"{header}: {value}\n" for header, value in msg.items())
    
    match_auth = re.search(r'Authentication-Results:.*?smtp.mailfrom=([\w\.-]+)', headers_str, re.I)
    if match_auth:
        data["Domain"] = match_auth.group(1).lower()
    else:
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

    # --- ID Extraction Logic ---
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


def fetch_emails(start_date, end_date, mailbox="inbox", use_uid_since=False, last_uid=None, current_batch_id=0):
    """
    Fetch emails. Assigns the current_batch_id to all fetched rows.
    """
    results = []
    
    start_date_str = start_date.strftime("%d-%b-%Y")
    day_after_end = end_date + datetime.timedelta(days=1)
    day_after_end_str = day_after_end.strftime("%d-%b-%Y")
    
    new_last_uid = last_uid
    
    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(st.session_state.email_input, st.session_state.password_input)
        imap.select(mailbox)

        if mailbox == "inbox" and use_uid_since and last_uid:
             criteria = f'(UID {int(last_uid)+1}:* SINCE {start_date_str} BEFORE {day_after_end_str})'
        else:
             criteria = f'(SINCE {start_date_str} BEFORE {day_after_end_str})'

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
                    email_data["Batch_ID"] = current_batch_id # Assign Batch ID
                    results.append(email_data)
            
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


def process_fetch_results(new_df, new_uid, target_df):
    """Handles concatenation, deduplication, and sorting for main DF."""
    
    if not target_df.empty:
        # Deduplicate based on Message-ID. We assume the *new* fetch is preferred if duplicates occur,
        # but usually we just filter out if it already exists.
        seen_ids = set(target_df["Message-ID"].dropna())
        new_df = new_df[~new_df["Message-ID"].isin(seen_ids)].copy()

    if not new_df.empty:
        combined_df = pd.concat([new_df, target_df], ignore_index=True)
        # Sort by Batch_ID descending so newest batches are on top
        combined_df = combined_df.sort_values(
            by='Batch_ID', 
            ascending=False, 
            ignore_index=True
        )
        return combined_df, len(new_df), new_uid
    
    return target_df, 0, new_uid


# --- Styling Functions ---

def get_batch_color(batch_id):
    """
    Generates a random pastel color based on the batch_id.
    Using HSL ensures the color is always light (High Lightness) and pastel (Low Saturation).
    """
    if batch_id == 0 or pd.isna(batch_id):
        return ''
    
    # Use a golden angle approximation to make sure consecutive batch IDs have distinct colors
    hue = (int(batch_id) * 137.508) % 360
    # Saturation 60-70% (Pastel), Lightness 92% (Very Light background)
    return f'background-color: hsl({hue}, 70%, 92%)'

def highlight_main_table(row):
    """
    Applies styling logic:
    1. Failed Auth -> Red Background (Highest Priority).
    2. Batch ID -> Unique Pastel Background (Secondary Priority).
    """
    # 1. Check for Failed Authentication
    spf_status = row.get('SPF', '')
    dkim_status = row.get('DKIM', '')
    dmarc_status = row.get('DMARC', '')

    failed = (spf_status != 'pass') or \
             (dkim_status != 'pass') or \
             (dmarc_status != 'pass')

    if failed:
        # Red takes priority over batch color
        style = 'background-color: rgba(255, 0, 0, 0.2)'
        return [style] * len(row)

    # 2. Apply Batch Color if Auth Passed
    batch_id = row.get('Batch_ID', 0)
    batch_style = get_batch_color(batch_id)
    
    return [batch_style] * len(row)


def highlight_failed_auth(row):
    """Always red background for the specific failed table."""
    style = 'background-color: rgba(255, 0, 0, 0.2)'
    return [style] * len(row)


# --- Action Buttons ---
colA, colB = st.columns([1.5, 2])

# Generate dynamic labels
if IS_DEFAULT_TODAY:
    initial_text = "📥 Fetch Today's Mails"
    incremental_text = "🔄 Fetch New Mails"
    range_text = "today's emails."
else:
    if IS_SINGLE_DAY:
        range_label = f" ({START_DATE})"
    else:
        range_label = f" ({START_DATE} to {END_DATE})"
    initial_text = f"🗓️ Fetch Range {range_label}"
    incremental_text = f"🔄 Fetch New {range_label}"
    range_text = f"emails in the range {range_label}."
    
button_label = incremental_text if not st.session_state.df.empty else initial_text
button_help = f"Fetches {'new emails incrementally' if not st.session_state.df.empty else 'all emails'} for {range_text}."


with colA:
    if st.button(button_label, help=button_help):
        
        # Increment batch counter for this new action
        st.session_state.batch_counter += 1
        current_batch = st.session_state.batch_counter

        use_uid_fetch = not st.session_state.df.empty and st.session_state.last_uid is not None

        with st.spinner(f"Fetching {range_text} (Batch #{current_batch})..."):
            
            # Fetch Inbox
            inbox_df, new_uid = fetch_emails(
                START_DATE, 
                END_DATE, 
                "inbox", 
                use_uid_since=use_uid_fetch, 
                last_uid=st.session_state.last_uid,
                current_batch_id=current_batch
            )
            
            # Fetch Spam
            spam_df, _ = fetch_emails(
                START_DATE, 
                END_DATE, 
                "[Gmail]/Spam", 
                use_uid_since=False,
                current_batch_id=current_batch
            )
            
            df_new = pd.concat([inbox_df, spam_df], ignore_index=True)
            
            # Process
            st.session_state.df, fetched_count, st.session_state.last_uid = process_fetch_results(
                df_new, new_uid, st.session_state.df
            )
                
            if fetched_count > 0:
                st.success(f"✅ Fetched {fetched_count} new emails (Batch #{current_batch}).")
            else:
                st.info(f"No new unique emails found for {range_text}.")


with colB:
    spam_range_label = f" ({START_DATE} to {END_DATE})" if not IS_SINGLE_DAY else f" ({START_DATE})"
    spam_button_label = f"🗑️ Fetch Spam Only"

    if st.button(spam_button_label, help=f"Fetches all unique spam emails."):
         
         # Increment batch counter
         st.session_state.batch_counter += 1
         current_batch = st.session_state.batch_counter

         with st.spinner(f"Fetching spam folder..."):
            spam_df_new, _ = fetch_emails(
                START_DATE, 
                END_DATE, 
                "[Gmail]/Spam", 
                use_uid_since=False,
                current_batch_id=current_batch
            )
            
            st.session_state.spam_df, fetched_count, _ = process_fetch_results(
                spam_df_new, None, st.session_state.spam_df
            )
            
            if fetched_count > 0:
                st.success(f"✅ Added {fetched_count} unique spam emails.")
            else:
                st.info(f"No new unique spam emails found.")

# --- Inbox + Spam Display ---
st.subheader("📬 Processed Emails")
# Added Batch_ID to display mainly for debugging visual, but removed from final list if you want it cleaner
inbox_cols = ["Subject", "Date", "Domain", "SPF", "DKIM", "DMARC", "Type", "Mailbox", "Batch_ID"] 

if not st.session_state.df.empty:
    # Create a view for display
    display_df = st.session_state.df.reindex(columns=inbox_cols, fill_value="-")
    
    # Apply the styling logic (Failed=Red, otherwise Batch=Color)
    styled_display_df = display_df.style.apply(highlight_main_table, axis=1)
    
    st.dataframe(styled_display_df, use_container_width=True)
else:
    st.info(f"No email data yet. Click '{initial_text}' to begin.")

# --- Failed Auth Display ---
if not st.session_state.df.empty:
    failed_df = st.session_state.df[
        (st.session_state.df["SPF"] != "pass") |
        (st.session_state.df["DKIM"] != "pass") |
        (st.session_state.df["DMARC"] != "pass")
    ]

    if not failed_df.empty:
        st.subheader("❌ Failed Auth Emails")
        failed_cols = ["Subject", "Domain", "SPF", "DKIM", "DMARC", "Type", "Sub ID", "Mailbox"]
        
        styled_failed_df = failed_df[failed_cols].style.apply(
            highlight_failed_auth, 
            axis=1
        )
        
        st.dataframe(styled_failed_df, use_container_width=True)
    else:
        st.success("✅ All fetched emails passed SPF, DKIM, and DMARC.")

# --- Spam Folder Display ---
if not st.session_state.spam_df.empty:
    st.subheader("🚫 Spam Folder Emails")
    spam_cols = ["Subject", "Date", "Domain", "Type", "Mailbox", "Batch_ID"]
    display_spam_df = st.session_state.spam_df.reindex(columns=spam_cols, fill_value="-")
    
    styled_spam_df = display_spam_df.style.apply(
        highlight_main_table, 
        axis=1
    )
    
    st.dataframe(styled_spam_df, use_container_width=True)
