import streamlit as st
import imaplib
import email
from email.header import decode_header
import datetime
import re
import pandas as pd

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

# --- Email + Password + Refresh Row ---
with st.container():
    col1, col2, col3 = st.columns([3, 3, 1.2])

    with col1:
        email_input = st.text_input("📧 Gmail Address", key="email_box")

    with col2:
        password_input = st.text_input("🔐 App Password", type="password", key="pwd_box")

    with col3:
        st.markdown("####")  # spacing alignment
        if st.button("🔁", help="Clear email and password"):
            for key in list(st.session_state.keys()):
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

def parse_email_message(msg):
    """Extracts all relevant details from an email message object."""
    data = {
        "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
        "Date": msg.get("Date", "No Date"),
        "SPF": "-", "DKIM": "-", "DMARC": "-", "Domain": "-",
        "Type": "-", "Sub ID": "-", "Message-ID": msg.get("Message-ID", "")
    }

    headers = ''.join(f"{header}: {value}\n" for header, value in msg.items())
    match_auth = re.search(r'Authentication-Results:.*?smtp.mailfrom=([\w\.-]+)', headers, re.I)
    if match_auth:
        data["Domain"] = match_auth.group(1).lower()
    else:
        from_header = decode_mime_words(msg.get('From', ''))
        match = re.search(r'@([\w\.-]+)', from_header)
        if match:
            data["Domain"] = match.group(1).lower()

    spf_match = re.search(r'spf=(\w+)', headers, re.I)
    dkim_match = re.search(r'dkim=(\w+)', headers, re.I)
    dmarc_match = re.search(r'dmarc=(\w+)', headers, re.I)
    if spf_match: data["SPF"] = spf_match.group(1).lower()
    if dkim_match: data["DKIM"] = dkim_match.group(1).lower()
    if dmarc_match: data["DMARC"] = dmarc_match.group(1).lower()

    # Extract Type and Sub ID from Message-ID
    message_id = msg.get("Message-ID", "")
    if message_id:
        sub_id_match = re.search(r'(GTC-[^@_]+|GMFP-[^@_]+)', message_id, re.I)
        if sub_id_match:
            data["Sub ID"] = sub_id_match.group(1)
        
        msg_id_lower = message_id.lower()
        if 'gtc' in msg_id_lower:
            data["Type"] = 'FPTC'
        elif 'gmfp' in msg_id_lower:
            data["Type"] = 'FP'
            
    return data

def fetch_emails(last_uid=None, mailbox="inbox"):
    """Fetch emails from a given mailbox (Inbox or Spam)."""
    results = []
    new_last_uid = last_uid
    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(st.session_state.email_input, st.session_state.password_input)
        imap.select(mailbox)

        today = datetime.datetime.now().strftime("%d-%b-%Y")
        criteria = f'(UID {int(last_uid)+1}:* SINCE {today})' if last_uid and mailbox=="inbox" else f'(SINCE {today})'
        
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
                    results.append(email_data)
            if mailbox == "inbox":
                new_last_uid = uid_decoded
        imap.logout()
    except Exception as e:
        st.error(f"❌ Error fetching from {mailbox}: {str(e)}")
    return pd.DataFrame(results), new_last_uid

def fetch_all_emails(last_uid=None):
    """Fetch from Inbox and Spam together, avoiding duplicates."""
    inbox_df, new_uid = fetch_emails(last_uid, "inbox")
    spam_df, _ = fetch_emails(None, "[Gmail]/Spam")

    combined_df = pd.concat([inbox_df, spam_df], ignore_index=True)

    # Drop duplicates using Message-ID
    if not st.session_state.df.empty:
        seen_ids = set(st.session_state.df["Message-ID"].dropna())
        combined_df = combined_df[~combined_df["Message-ID"].isin(seen_ids)]

    return combined_df, new_uid

def fetch_spam_emails():
    """Fetch today's spam emails (standalone button, avoid duplicates)."""
    spam_df, _ = fetch_emails(None, "[Gmail]/Spam")

    if not st.session_state.spam_df.empty:
        seen_ids = set(st.session_state.spam_df["Message-ID"].dropna())
        spam_df = spam_df[~spam_df["Message-ID"].isin(seen_ids)]

    return spam_df

# --- Action Buttons ---
colA, colB = st.columns(2)

with colA:
    button_label = "🔄 Fetch New Emails" if not st.session_state.df.empty else "📥 Fetch Today's Emails"
    if st.button(button_label):
        with st.spinner("Fetching emails (Inbox + Spam)..."):
            df, new_uid = fetch_all_emails(st.session_state.last_uid)
            if not df.empty:
                st.session_state.df = pd.concat([df, st.session_state.df], ignore_index=True)
                st.session_state.last_uid = new_uid
                st.success(f"✅ Fetched {len(df)} new unique emails (Inbox + Spam).")
            else:
                st.info("No new emails found.")

with colB:
    if st.button("🗑️ List Today's Spam"):
         with st.spinner("Fetching today's spam..."):
            spam_df = fetch_spam_emails()
            if not spam_df.empty:
                st.session_state.spam_df = pd.concat([spam_df, st.session_state.spam_df], ignore_index=True)
                st.success(f"✅ Added {len(spam_df)} unique spam emails for today.")
            else:
                st.info("No new spam emails found for today.")

# --- Inbox + Spam Display ---
st.subheader("📬 Today's Processed Emails (Inbox + Spam)")
inbox_cols = ["Subject", "Date", "Domain", "SPF", "DKIM", "DMARC", "Type", "Mailbox"]

if not st.session_state.df.empty:
    display_df = st.session_state.df.reindex(columns=inbox_cols, fill_value="-")
    st.dataframe(display_df)
else:
    st.info("No email data yet. Click 'Fetch Today's Emails' to begin.")

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
        st.dataframe(failed_df[failed_cols])
    else:
        st.success("✅ All fetched emails passed SPF, DKIM, and DMARC.")

# --- Spam Folder Display ---
if not st.session_state.spam_df.empty:
    st.subheader("🚫 Today's Spam Folder Emails")
    spam_cols = ["Subject", "Date", "Domain", "Type", "Mailbox"]
    display_spam_df = st.session_state.spam_df.reindex(columns=spam_cols, fill_value="-")
    st.dataframe(display_spam_df)
