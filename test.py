import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
import datetime
import re
import pandas as pd
from urllib.parse import urlparse

# ---------------- PAGE SETUP ----------------
st.set_page_config(page_title="Email Auth Checker", layout="wide")
st.title("📧 Email Authentication Report (SPF/DKIM/DMARC)")

# ---------------- DATAFRAME COLUMNS ----------------
DF_COLS = [
    "Subject", "Date", "From",
    "SPF", "DKIM", "DMARC",
    "Domain", "Message-ID",
    "Tracking Domain", "List-Unsubscribe",
    "Unsubscribe Link", "Open Pixel", "Logo"
]

if "df" not in st.session_state:
    st.session_state.df = pd.DataFrame(columns=DF_COLS)

if "tracking_df" not in st.session_state:
    st.session_state.tracking_df = pd.DataFrame()

if "show_deep" not in st.session_state:
    st.session_state.show_deep = False

# ---------------- ORIGINAL INPUT ROW ----------------
today = datetime.date.today()

col1, col2, col3 = st.columns(3)

with col1:
    email_input = st.text_input("📧 Gmail Address")

with col2:
    password_input = st.text_input("🔐 App Password", type="password")

with col3:
    date_range = st.date_input(
        "Select Date Range",
        value=(today, today),
        max_value=today
    )

if not email_input or not password_input:
    st.warning("Please enter Gmail and App Password")
    st.stop()

if isinstance(date_range, tuple):
    start_date, end_date = date_range
else:
    start_date = end_date = date_range

# ---------------- UTILITIES ----------------

def decode_mime_words(s):
    if not s:
        return ""
    out = ""
    for part, enc in decode_header(s):
        if isinstance(part, bytes):
            out += part.decode(enc or "utf-8", errors="ignore")
        else:
            out += part
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

# ---------------- FETCH EMAILS (HEADER ONLY) ----------------

def fetch_emails():

    results = []

    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(email_input, password_input)
    imap.select("inbox")

    start_str = start_date.strftime("%d-%b-%Y")
    end_str = (end_date + datetime.timedelta(days=1)).strftime("%d-%b-%Y")

    status, data = imap.search(None, f'(SINCE {start_str} BEFORE {end_str})')
    ids = data[0].split()

    for num in ids:
        status, msg_data = imap.fetch(num, '(BODY.PEEK[HEADER])')
        for part in msg_data:
            if isinstance(part, tuple):
                msg = email.message_from_bytes(part[1])

                raw_from = decode_mime_words(msg.get("From", ""))
                display_name, email_addr = parseaddr(raw_from)
                clean_from = display_name if display_name else email_addr

                headers_str = ''.join(f"{h}: {v}\n" for h, v in msg.items())

                row = {
                    "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
                    "Date": format_date_ist(msg.get("Date", "")),
                    "From": clean_from,
                    "SPF": "-", "DKIM": "-", "DMARC": "-",
                    "Domain": "-",
                    "Message-ID": decode_mime_words(msg.get("Message-ID", "")),
                    "Tracking Domain": "-",
                    "List-Unsubscribe": "-",
                    "Unsubscribe Link": "-",
                    "Open Pixel": "-",
                    "Logo": "-"
                }

                match_auth = re.search(r'smtp.mailfrom=([\w\.-]+)', headers_str, re.I)
                if match_auth:
                    row["Domain"] = match_auth.group(1).lower()

                for key in ["spf", "dkim", "dmarc"]:
                    m = re.search(fr'{key}=(\w+)', headers_str, re.I)
                    if m:
                        row[key.upper()] = m.group(1).lower()

                results.append(row)

    imap.logout()
    return pd.DataFrame(results)

# ---------------- FETCH BUTTON ----------------

if st.button("📥 Fetch Emails"):
    with st.spinner("Fetching emails..."):
        st.session_state.df = fetch_emails()
    st.success("Emails fetched successfully.")

# ---------------- DISPLAY MAIN TABLE ----------------

if not st.session_state.df.empty:
    display_df = st.session_state.df.copy()
    display_df.index = display_df.index + 1
    st.subheader("📬 Processed Emails")
    st.dataframe(display_df, use_container_width=True)

# ---------------- TOGGLE DEEP EXTRACTION ----------------

st.markdown("---")

if st.button("🔬 Enable Deep Tracking Extraction"):
    st.session_state.show_deep = not st.session_state.show_deep

# ---------------- DEEP MODULE ----------------

if st.session_state.show_deep and not st.session_state.df.empty:

    st.subheader("Deep Tracking Extraction")

    domain_input = st.text_area(
        "Paste tracking domains (one per line)",
        height=150
    )

    if st.button("🚀 Run Tracking Extraction") and domain_input.strip():

        selected_domains = [
            d.strip().lower()
            for d in domain_input.splitlines()
            if d.strip()
        ]

        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_input, password_input)
        imap.select("inbox")

        tracking_rows = []

        for idx, row in st.session_state.df.iterrows():

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
                        links = re.findall(r'https?://[^\s"\'<>]+', body_html)
                        tracking_links = [l for l in links if tracking_domain in l]

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

        st.session_state.tracking_df = pd.DataFrame(tracking_rows)
        st.success("Tracking extraction complete.")

# ---------------- DISPLAY TRACKING RESULTS ----------------

if not st.session_state.tracking_df.empty:
    tracking_display = st.session_state.tracking_df.copy()
    tracking_display.index = tracking_display.index + 1
    st.subheader("📊 Tracking Extraction Results")
    st.dataframe(tracking_display, use_container_width=True)
