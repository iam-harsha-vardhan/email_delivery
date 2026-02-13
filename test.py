import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
import datetime
import re
import pandas as pd
import base64
from urllib.parse import urlparse

# ---------------- PAGE SETUP ----------------
st.set_page_config(page_title="Email Auth Checker", layout="wide")
st.title("📧 Email Authentication & Tracking Intelligence")

# ---------------- DATAFRAME COLUMNS ----------------
DF_COLS = [
    "Subject", "Date", "From",
    "SPF", "DKIM", "DMARC",
    "Domain", "Type", "Sub ID",
    "Message-ID", "Mailbox", "Batch_ID",
    "Tracking Domain", "List-Unsubscribe",
    "Unsubscribe Link", "Open Pixel", "Logo"
]

# ---------------- SESSION STATE ----------------
if 'df' not in st.session_state:
    st.session_state.df = pd.DataFrame(columns=DF_COLS)
if 'last_uid' not in st.session_state:
    st.session_state.last_uid = None
if 'batch_counter' not in st.session_state:
    st.session_state.batch_counter = 0

today = datetime.date.today()

# ---------------- INPUTS ----------------
email_input = st.text_input("📧 Gmail Address")
password_input = st.text_input("🔐 App Password", type="password")

deep_extract = st.checkbox(
    "🔬 Extract tracking links (slow — use only when needed)"
)

if not email_input or not password_input:
    st.warning("Enter Gmail + App Password")
    st.stop()

# ---------------- UTILITIES ----------------

def decode_mime_words(s):
    if not s: return ""
    out = ""
    for part, enc in decode_header(s):
        try:
            if isinstance(part, bytes):
                out += part.decode(enc or 'utf-8', errors='ignore')
            else:
                out += part
        except:
            out += part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part)
    return out.strip()

def format_date_ist(date_str):
    try:
        dt = parsedate_to_datetime(date_str)
        ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
        return dt.astimezone(ist).strftime("%d-%b-%Y %I:%M %p")
    except:
        return "-"

def get_domain_from_url(url):
    try:
        return urlparse(url).netloc.lower()
    except:
        return ""

# ---------------- EMAIL PARSER ----------------

def parse_email_message(msg, batch_id):

    raw_from = decode_mime_words(msg.get("From", ""))
    display_name, email_addr = parseaddr(raw_from)
    clean_from = display_name if display_name else email_addr

    raw_date = msg.get("Date", "")

    data = {
        "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
        "Date": format_date_ist(raw_date),
        "From": clean_from,
        "SPF": "-", "DKIM": "-", "DMARC": "-", "Domain": "-",
        "Type": "-", "Sub ID": "-",
        "Message-ID": decode_mime_words(msg.get("Message-ID", "")),
        "Mailbox": "-",
        "Batch_ID": batch_id,
        "Tracking Domain": "-",
        "List-Unsubscribe": "-",
        "Unsubscribe Link": "-",
        "Open Pixel": "-",
        "Logo": "-"
    }

    headers_str = ''.join(f"{h}: {v}\n" for h, v in msg.items())

    # Extract domain from Authentication Results
    match_auth = re.search(r'smtp.mailfrom=([\w\.-]+)', headers_str, re.I)
    if match_auth:
        data["Domain"] = match_auth.group(1).lower()

    # SPF/DKIM/DMARC
    for key in ["spf", "dkim", "dmarc"]:
        m = re.search(fr'{key}=(\w+)', headers_str, re.I)
        if m:
            data[key.upper()] = m.group(1).lower()

    # ---------------- TRACKING EXTRACTION ----------------
    if deep_extract:

        # Extract List-Unsubscribe
        lu_match = re.search(r'List-Unsubscribe:.*', headers_str, re.I)
        tracking_domain = ""

        if lu_match:
            lu_urls = re.findall(r'<([^>]+)>', lu_match.group(0))
            for url in lu_urls:
                if url.startswith("http"):
                    data["List-Unsubscribe"] = url
                    tracking_domain = get_domain_from_url(url)
                    data["Tracking Domain"] = tracking_domain
                    break

        # Extract HTML body
        body_html = ""

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    body_html = part.get_payload(decode=True).decode(errors="ignore")
                    break
        else:
            if msg.get_content_type() == "text/html":
                body_html = msg.get_payload(decode=True).decode(errors="ignore")

        if tracking_domain and body_html:

            all_links = re.findall(r'https?://[^\s"\'<>]+', body_html)
            tracking_links = [l for l in all_links if tracking_domain in l]

            for link in tracking_links:
                l = link.lower()

                if "unsub" in l or "optout" in l:
                    data["Unsubscribe Link"] = link

                elif re.search(r'pixel|open|track|view', l):
                    data["Open Pixel"] = link

                elif re.search(r'\.(png|jpg|jpeg|gif|svg)$', l):
                    data["Logo"] = link

    return data

# ---------------- FETCH ----------------

def fetch_emails(batch_id):

    results = []

    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(email_input, password_input)
    imap.select("inbox")

    status, data = imap.search(None, "ALL")
    ids = data[0].split()[-50:]  # last 50 emails only

    for num in ids:
        fetch_mode = '(BODY.PEEK[])' if deep_extract else '(BODY.PEEK[HEADER])'
        status, msg_data = imap.fetch(num, fetch_mode)

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                email_data = parse_email_message(msg, batch_id)
                email_data["Mailbox"] = "Inbox"
                results.append(email_data)

    imap.logout()
    return pd.DataFrame(results, columns=DF_COLS)

# ---------------- BUTTON ----------------

if st.button("📥 Fetch Emails"):

    st.session_state.batch_counter += 1
    batch_id = st.session_state.batch_counter

    with st.spinner("Fetching emails..."):
        df_new = fetch_emails(batch_id)
        st.session_state.df = pd.concat([df_new, st.session_state.df], ignore_index=True)

# ---------------- DISPLAY ----------------

if not st.session_state.df.empty:

    display_df = st.session_state.df.copy()
    display_df.index = display_df.index + 1

    st.subheader("📬 Processed Emails")
    st.dataframe(display_df, use_container_width=True)

    # Failed Auth
    failed = display_df[
        (display_df["SPF"] != "pass") |
        (display_df["DKIM"] != "pass") |
        (display_df["DMARC"] != "pass")
    ]

    if not failed.empty:
        st.subheader("❌ Failed Auth Emails")
        st.dataframe(failed, use_container_width=True)
