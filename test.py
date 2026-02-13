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

# ---------------- PAGE SETUP ----------------
st.set_page_config(page_title="Email Auth Checker", layout="wide")
st.title("📧 Email Authentication Report (SPF/DKIM/DMARC)")

DF_COLS = [
    "Subject", "Date", "From",
    "SPF", "DKIM", "DMARC",
    "Domain", "Type", "Sub ID",
    "Message-ID", "Mailbox", "Batch_ID"
]

# ---------------- SESSION STATE ----------------
if 'df' not in st.session_state:
    st.session_state.df = pd.DataFrame(columns=DF_COLS)
if 'spam_df' not in st.session_state:
    st.session_state.spam_df = pd.DataFrame(columns=DF_COLS)
if 'last_uid' not in st.session_state:
    st.session_state.last_uid = None
if 'batch_counter' not in st.session_state:
    st.session_state.batch_counter = 0
if 'show_tracking_tool' not in st.session_state:
    st.session_state.show_tracking_tool = False

today = datetime.date.today()
if 'fetch_dates' not in st.session_state:
    st.session_state.fetch_dates = (today, today)

# ---------------- INPUT ROW ----------------
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
            s, e = date_range
            if s > e:
                s, e = e, s
            st.session_state.fetch_dates = (s, e)
        elif isinstance(date_range, datetime.date):
            st.session_state.fetch_dates = (date_range, date_range)

    with col4:
        st.markdown("####")
        if st.button("🔁"):
            for key in list(st.session_state.keys()):
                if key not in ['date_box', 'fetch_dates']:
                    del st.session_state[key]
            st.rerun()

if not email_input or not password_input:
    st.warning("Please enter Gmail & App Password.")
    st.stop()

START_DATE, END_DATE = st.session_state.fetch_dates

# ---------------- UTILITIES ----------------

def decode_mime_words(s):
    if not s:
        return ""
    out = ""
    for part, enc in decode_header(s):
        try:
            if isinstance(part, bytes):
                out += part.decode(enc or 'utf-8', errors='ignore')
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

def extract_id_details(search_string, data):
    m = re.search(r'(GTC-[^@_]+|GMFP-[^@_]+|GRM-[^@_]+|GRTC-[^@_]+)', search_string, re.I)
    if m:
        sid = m.group(1)
        data["Sub ID"] = sid
        l = sid.lower()
        if 'grm' in l:
            data["Type"] = 'FPR'
        elif 'gmfp' in l:
            data["Type"] = 'FP'
        elif 'gtc' in l:
            data["Type"] = 'FPTC'
        elif 'grtc' in l:
            data["Type"] = 'FPRTC'
        return True
    return False

def parse_email_message(msg, batch_id):

    raw_date = msg.get("Date", "")
    from_header = decode_mime_words(msg.get("From", ""))

    display_name = "-"
    domain = "-"

    if "<" in from_header and "@" in from_header:
        try:
            display_name = from_header.split("<")[0].strip().strip('"')
            email_part = from_header.split("<")[1].split(">")[0]
            domain = email_part.split("@")[1].lower()
        except:
            pass

    data = {
        "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
        "Date": format_date_ist(raw_date),
        "From": display_name,
        "SPF": "-", "DKIM": "-", "DMARC": "-",
        "Domain": domain,
        "Type": "-", "Sub ID": "-",
        "Message-ID": decode_mime_words(msg.get("Message-ID", "")),
        "Batch_ID": batch_id
    }

    headers_str = ''.join(f"{h}: {v}\n" for h, v in msg.items())

    for key in ["spf", "dkim", "dmarc"]:
        m = re.search(fr'{key}=(\w+)', headers_str, re.I)
        if m:
            data[key.upper()] = m.group(1).lower()

    if not extract_id_details(headers_str, data):
        for h, v in msg.items():
            if not v:
                continue
            for part in str(v).split('_'):
                if len(part) < 20:
                    continue
                try:
                    dec = base64.b64decode(part + '=' * (-len(part) % 4)).decode('utf-8', 'ignore')
                    if extract_id_details(dec, data):
                        break
                except:
                    pass
            if data["Type"] != "-":
                break

    return data

# ---------------- FETCH ----------------

def fetch_emails(start_date, end_date, mailbox="inbox", use_uid_since=False, last_uid=None, batch_id=0):

    results = []
    s = start_date.strftime("%d-%b-%Y")
    e = (end_date + datetime.timedelta(days=1)).strftime("%d-%b-%Y")

    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(email_input, password_input)
    imap.select(mailbox)

    if mailbox == "inbox" and use_uid_since and last_uid:
        criteria = f'(UID {int(last_uid)+1}:* SINCE {s} BEFORE {e})'
    else:
        criteria = f'(SINCE {s} BEFORE {e})'

    status, data = imap.uid('search', None, criteria)
    uids = data[0].split()
    new_last = last_uid

    for uid in uids:
        _, msg_data = imap.uid('fetch', uid, '(BODY.PEEK[HEADER])')
        for part in msg_data:
            if isinstance(part, tuple):
                msg = email.message_from_bytes(part[1])
                d = parse_email_message(msg, batch_id)
                d["Mailbox"] = "Inbox" if mailbox == "inbox" else "Spam"
                results.append(d)

        if mailbox == "inbox":
            new_last = uid.decode()

    imap.logout()
    return pd.DataFrame(results, columns=DF_COLS), new_last

# ---------------- FETCH BUTTON ----------------

if st.button("📥 Fetch Emails"):
    st.session_state.batch_counter += 1
    batch = st.session_state.batch_counter

    inbox_df, new_uid = fetch_emails(
        START_DATE, END_DATE, "inbox",
        st.session_state.last_uid is not None,
        st.session_state.last_uid,
        batch
    )

    spam_df, _ = fetch_emails(
        START_DATE, END_DATE, "[Gmail]/Spam",
        False, None, batch
    )

    df_new = pd.concat([inbox_df, spam_df], ignore_index=True)
    st.session_state.df = pd.concat([df_new, st.session_state.df], ignore_index=True)
    st.session_state.last_uid = new_uid

    st.success(f"Batch #{batch} fetched. Total: {len(df_new)} emails.")

# ---------------- DISPLAY MAIN ----------------

if not st.session_state.df.empty:

    inbox_cols = ["Subject", "Date", "From", "Domain",
                  "SPF", "DKIM", "DMARC",
                  "Type", "Mailbox", "Batch_ID"]

    display_df = st.session_state.df[inbox_cols].copy()
    display_df.index += 1

    st.subheader("📬 Processed Emails")
    st.dataframe(display_df, use_container_width=True,
                 column_config={"Batch_ID": None})

# ---------------- FAILED AUTH ----------------

if not st.session_state.df.empty:
    failed_df = st.session_state.df[
        (st.session_state.df["SPF"] != "pass") |
        (st.session_state.df["DKIM"] != "pass") |
        (st.session_state.df["DMARC"] != "pass")
    ]

    if not failed_df.empty:
        failed_cols = ["Subject", "Date", "From",
                       "Domain", "SPF", "DKIM", "DMARC",
                       "Type", "Sub ID", "Mailbox"]

        failed_display = failed_df[failed_cols].copy()
        failed_display.index += 1

        st.subheader("❌ Failed Auth Emails")
        st.dataframe(failed_display, use_container_width=True)

# ---------------- TRACKING TOOL ----------------

st.markdown("---")

if st.button("🔗 Extract Tracking Links"):
    st.session_state.show_tracking_tool = not st.session_state.show_tracking_tool

if st.session_state.show_tracking_tool and not st.session_state.df.empty:

    st.subheader("🔬 Deep Tracking Extraction")
    domain_input = st.text_area("Paste domains (one per line)", height=120)

    if st.button("Run Extraction") and domain_input.strip():

        selected_domains = [d.strip().lower() for d in domain_input.splitlines() if d.strip()]
        results = []

        UNSUB_KEYWORDS = [
            "preferences", "rmv", "checkout",
            "opt", "optout", "remove", "manage"
        ]

        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_input, password_input)
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

                body = ""
                if msg.is_multipart():
                    for p in msg.walk():
                        if p.get_content_type() == "text/html":
                            body = p.get_payload(decode=True).decode(errors="ignore")
                            break
                else:
                    if msg.get_content_type() == "text/html":
                        body = msg.get_payload(decode=True).decode(errors="ignore")

                if not body:
                    continue

                links = re.findall(r'https?://[^\s"\'<>]+', body)
                domain_links = [l for l in links if row["Domain"] in l.lower()]

                list_unsub = "-"
                unsub = "-"
                logo = "-"
                pixel = "-"

                for link in domain_links:
                    low = link.lower()

                    if "list-unsub" in low:
                        list_unsub = link

                    elif any(k in low for k in UNSUB_KEYWORDS):
                        unsub = link

                    elif re.search(r'\.(jpg|jpeg|png|gif|svg)', low):
                        logo = link

                remaining = [l for l in domain_links if l not in [list_unsub, unsub, logo]]

                if remaining:
                    pixel = remaining[0]

                results.append({
                    "Subject": row["Subject"],
                    "Date": row["Date"],
                    "From": row["From"],
                    "Sender Domain": row["Domain"],
                    "List-Unsubscribe": list_unsub,
                    "Unsubscribe Link": unsub,
                    "Open Pixel": pixel,
                    "Logo": logo
                })

        imap.logout()

        if results:
            df_links = pd.DataFrame(results)
            df_links.index += 1
            st.subheader("📊 Tracking Link Results")
            st.dataframe(df_links, use_container_width=True)
        else:
            st.info("No matching domain links found.")
