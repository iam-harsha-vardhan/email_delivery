import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
import datetime
import re
import pandas as pd
import base64
import urllib.parse

# --- Page Setup ---
st.set_page_config(page_title="Email Auth Checker", layout="wide")
st.title("📧 Email Authentication Report (SPF/DKIM/DMARC)")

# Define the columns (Batch_ID is included for logic, but will be hidden)
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
if 'batch_counter' not in st.session_state:
    st.session_state.batch_counter = 0

# --- Initialize or update dates ---
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
            key="date_box"
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
    decoded_string = ""
    if not s:
        return decoded_string
    for part, encoding in decode_header(s):
        try:
            if isinstance(part, bytes):
                decoded_string += part.decode(encoding or 'utf-8', errors='ignore')
            else:
                decoded_string += part
        except:
            if isinstance(part, bytes):
                decoded_string += part.decode('utf-8', errors='ignore')
            else:
                decoded_string += str(part)
    return decoded_string.strip()

def format_date_ist(date_str):
    if not date_str:
        return "-"
    try:
        dt = parsedate_to_datetime(date_str)
        ist_offset = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
        dt_ist = dt.astimezone(ist_offset)
        return dt_ist.strftime("%d-%b-%Y %I:%M %p")
    except Exception:
        return str(date_str)

def extract_id_details(search_string, data):
    sub_id_match = re.search(
        r'(GTC-[^@_]+|GMFP-[^@_]+|GRM-[^@_]+|GRTC-[^@_]+)', 
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
        elif 'grtc' in id_lower:
            data["Type"] = 'FPRTC'
        return True
    return False

def parse_email_message(msg, current_batch_id):
    raw_date = msg.get("Date", "")
    data = {
        "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
        "Date": format_date_ist(raw_date),
        "SPF": "-", "DKIM": "-", "DMARC": "-", "Domain": "-", 
        "Type": "-", "Sub ID": "-", 
        "Message-ID": decode_mime_words(msg.get("Message-ID", "")),
        "Batch_ID": current_batch_id 
    }

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
                except:
                    pass
            if data["Type"] != "-":
                break

    return data
# ===============================
# 🔗 OPTIONAL TRACKING LINK TOOL
# ===============================

if "show_tracking_tool" not in st.session_state:
    st.session_state.show_tracking_tool = False

st.markdown("---")

if st.button("🔗 Extract Tracking Links (Optional Tool)"):
    st.session_state.show_tracking_tool = not st.session_state.show_tracking_tool

if st.session_state.show_tracking_tool:

    st.subheader("🔬 Deep Tracking Extraction")

    domain_input = st.text_area(
        "Paste tracking domains (one per line)",
        height=150
    )

    if st.button("🚀 Run Link Extraction"):

        if not domain_input.strip():
            st.warning("Paste at least one domain.")
        elif st.session_state.df.empty:
            st.warning("No emails fetched yet.")
        else:

            selected_domains = [
                d.strip().lower()
                for d in domain_input.splitlines()
                if d.strip()
            ]

            tracking_results = []

            imap = imaplib.IMAP4_SSL("imap.gmail.com")
            imap.login(st.session_state.email_input, st.session_state.password_input)
            imap.select("inbox")

            for _, row in st.session_state.df.iterrows():

                if row["Domain"] not in selected_domains:
                    continue

                msg_id = row["Message-ID"]
                status, data = imap.search(None, f'(HEADER Message-ID "{msg_id}")')
                ids = data[0].split()
                if not ids:
                    continue

                status, msg_data = imap.fetch(ids[0], '(BODY.PEEK[])')

                for part in msg_data:
                    if not isinstance(part, tuple):
                        continue

                    msg = email.message_from_bytes(part[1])
                    headers_str = ''.join(f"{h}: {v}\n" for h, v in msg.items())

                    tracking_domain = "-"
                    list_unsub = "-"
                    unsub_link = "-"
                    open_pixel = "-"
                    logo = "-"

                    lu_match = re.search(r'List-Unsubscribe:.*', headers_str, re.I)
                    if lu_match:
                        urls = re.findall(r'<([^>]+)>', lu_match.group(0))
                        for u in urls:
                            if u.startswith("http"):
                                list_unsub = u
                                tracking_domain = urllib.parse.urlparse(u).netloc.lower()
                                break

                    body_html = ""
                    if msg.is_multipart():
                        for p in msg.walk():
                            if p.get_content_type() == "text/html":
                                body_html = p.get_payload(decode=True).decode(errors="ignore")
                                break

                    if tracking_domain != "-" and body_html:
                        links = re.findall(r'https?://[^\s"\'<>]+', body_html)
                        tracking_links = [l for l in links if tracking_domain in l]

                        for link in tracking_links:
                            l = link.lower()
                            if "unsub" in l:
                                unsub_link = link
                            elif re.search(r'pixel|open|track|view', l):
                                open_pixel = link
                            elif re.search(r'\.(png|jpg|jpeg|gif|svg)$', l):
                                logo = link

                    tracking_results.append({
                        "Subject": row["Subject"],
                        "Date": row["Date"],
                        "Domain": row["Domain"],
                        "Tracking Domain": tracking_domain,
                        "List-Unsubscribe": list_unsub,
                        "Unsubscribe Link": unsub_link,
                        "Open Pixel": open_pixel,
                        "Logo": logo
                    })

            imap.logout()

            if tracking_results:
                tracking_df = pd.DataFrame(tracking_results)
                tracking_df.index = tracking_df.index + 1
                st.subheader("📊 Tracking Link Results")
                st.dataframe(tracking_df, use_container_width=True)
            else:
                st.info("No tracking links found for selected domains.")
