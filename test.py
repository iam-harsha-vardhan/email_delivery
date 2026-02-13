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
st.title("📧 Email Authentication Report (SPF/DKIM/DMARC)")

DF_COLS = [
    "Subject", "Date", "From",
    "SPF", "DKIM", "DMARC",
    "Domain", "Type", "Sub ID",
    "Message-ID", "Mailbox", "Batch_ID",
    "Tracking Domain", "List-Unsubscribe",
    "Unsubscribe Link", "Open Pixel", "Logo"
]

# ---------------- SESSION STATE ----------------
if "df" not in st.session_state:
    st.session_state.df = pd.DataFrame(columns=DF_COLS)

if "tracking_df" not in st.session_state:
    st.session_state.tracking_df = pd.DataFrame()

if "last_uid" not in st.session_state:
    st.session_state.last_uid = None

if "batch_counter" not in st.session_state:
    st.session_state.batch_counter = 0

today = datetime.date.today()

# ---------------- EMAIL + PASSWORD ROW ----------------
col1, col2 = st.columns(2)

with col1:
    email_input = st.text_input("📧 Gmail Address")

with col2:
    password_input = st.text_input("🔐 App Password", type="password")

if not email_input or not password_input:
    st.warning("Enter Gmail + App Password")
    st.stop()

# ---------------- UTILITIES ----------------

def decode_mime_words(s):
    if not s:
        return ""
    out = ""
    for part, enc in decode_header(s):
        try:
            if isinstance(part, bytes):
                out += part.decode(enc or "utf-8", errors="ignore")
            else:
                out += part
        except:
            out += str(part)
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

# ---------------- PARSER ----------------

def parse_email_message(msg, batch_id):

    raw_from = decode_mime_words(msg.get("From", ""))
    display_name, email_addr = parseaddr(raw_from)
    clean_from = display_name if display_name else email_addr

    headers_str = ''.join(f"{h}: {v}\n" for h, v in msg.items())

    data = {
        "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
        "Date": format_date_ist(msg.get("Date", "")),
        "From": clean_from,
        "SPF": "-", "DKIM": "-", "DMARC": "-",
        "Domain": "-", "Type": "-", "Sub ID": "-",
        "Message-ID": decode_mime_words(msg.get("Message-ID", "")),
        "Mailbox": "Inbox",
        "Batch_ID": batch_id,
        "Tracking Domain": "-",
        "List-Unsubscribe": "-",
        "Unsubscribe Link": "-",
        "Open Pixel": "-",
        "Logo": "-"
    }

    match_auth = re.search(r'smtp.mailfrom=([\w\.-]+)', headers_str, re.I)
    if match_auth:
        data["Domain"] = match_auth.group(1).lower()

    for key in ["spf", "dkim", "dmarc"]:
        m = re.search(fr'{key}=(\w+)', headers_str, re.I)
        if m:
            data[key.upper()] = m.group(1).lower()

    return data

# ---------------- FETCH ----------------

def fetch_emails(batch_id):

    results = []

    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(email_input, password_input)
    imap.select("inbox")

    status, data = imap.search(None, "ALL")
    ids = data[0].split()

    for num in ids:
        status, msg_data = imap.fetch(num, '(BODY.PEEK[HEADER])')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                results.append(parse_email_message(msg, batch_id))

    imap.logout()
    return pd.DataFrame(results, columns=DF_COLS)

# ---------------- DEEP EXTRACTION ----------------

def deep_extract(df, selected_domains):

    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(email_input, password_input)
    imap.select("inbox")

    tracking_rows = []

    for idx, row in df.iterrows():

        if row["Domain"] not in selected_domains:
            continue

        msg_id = row["Message-ID"]
        if not msg_id:
            continue

        status, data = imap.search(None, f'(HEADER Message-ID "{msg_id}")')
        ids = data[0].split()

        if not ids:
            continue

        status, msg_data = imap.fetch(ids[0], '(BODY.PEEK[])')

        for part in msg_data:
            if isinstance(part, tuple):
                msg = email.message_from_bytes(part[1])

                headers_str = ''.join(f"{h}: {v}\n" for h, v in msg.items())

                lu_match = re.search(r'List-Unsubscribe:.*', headers_str, re.I)
                tracking_domain = ""

                if lu_match:
                    lu_urls = re.findall(r'<([^>]+)>', lu_match.group(0))
                    for url in lu_urls:
                        if url.startswith("http"):
                            tracking_domain = get_domain_from_url(url)
                            row["Tracking Domain"] = tracking_domain
                            row["List-Unsubscribe"] = url
                            break

                body_html = ""
                if msg.is_multipart():
                    for p in msg.walk():
                        if p.get_content_type() == "text/html":
                            body_html = p.get_payload(decode=True).decode(errors="ignore")
                            break

                if tracking_domain and body_html:
                    all_links = re.findall(r'https?://[^\s"\'<>]+', body_html)
                    tracking_links = [l for l in all_links if tracking_domain in l]

                    for link in tracking_links:
                        l = link.lower()
                        if "unsub" in l:
                            row["Unsubscribe Link"] = link
                        elif re.search(r'pixel|open|track|view', l):
                            row["Open Pixel"] = link
                        elif re.search(r'\.(png|jpg|jpeg|gif|svg)$', l):
                            row["Logo"] = link

                tracking_rows.append(row)

    imap.logout()
    return pd.DataFrame(tracking_rows)

# ---------------- FETCH BUTTON ----------------

if st.button("📥 Fetch Emails"):
    st.session_state.batch_counter += 1
    st.session_state.df = fetch_emails(st.session_state.batch_counter)
    st.success("Emails fetched successfully.")

# ---------------- DISPLAY MAIN TABLE ----------------

if not st.session_state.df.empty:

    display_df = st.session_state.df.copy()
    display_df.index = display_df.index + 1

    st.subheader("📬 Processed Emails")
    st.dataframe(display_df, use_container_width=True)

    failed = display_df[
        (display_df["SPF"] != "pass") |
        (display_df["DKIM"] != "pass") |
        (display_df["DMARC"] != "pass")
    ]

    if not failed.empty:
        st.subheader("❌ Failed Auth Emails")
        st.dataframe(failed, use_container_width=True)

# ---------------- DEEP TRACKING BOX (SAME PAGE) ----------------

st.markdown("---")
st.subheader("🔬 Deep Tracking Extraction")

domain_input = st.text_area(
    "Paste tracking domains (one per line)",
    height=150
)

if st.button("🚀 Extract Tracking") and domain_input.strip() and not st.session_state.df.empty:

    selected_domains = [
        d.strip().lower()
        for d in domain_input.splitlines()
        if d.strip()
    ]

    with st.spinner("Extracting tracking details..."):
        st.session_state.tracking_df = deep_extract(
            st.session_state.df,
            selected_domains
        )

    st.success("Tracking extraction complete.")

# ---------------- TRACKING RESULT TABLE ----------------

if not st.session_state.tracking_df.empty:

    tracking_display = st.session_state.tracking_df.copy()
    tracking_display.index = tracking_display.index + 1

    st.subheader("📊 Tracking Extraction Results")
    st.dataframe(tracking_display, use_container_width=True)
