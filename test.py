import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
import datetime
import re
import pandas as pd
import base64

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
        email_input = st.text_input("📧 Gmail Address")

    with col2:
        password_input = st.text_input("🔐 App Password", type="password")

    with col3:
        date_range = st.date_input(
            "Select Date Range",
            value=st.session_state.fetch_dates,
            max_value=today
        )

        if isinstance(date_range, tuple):
            s, e = date_range
            if s > e:
                s, e = e, s
            st.session_state.fetch_dates = (s, e)

    with col4:
        st.markdown("####")
        if st.button("🔁"):
            st.session_state.clear()
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

def parse_email_message(msg, batch_id):
    raw_date = msg.get("Date", "")
    from_header = decode_mime_words(msg.get("From", ""))

    display_name = "-"
    domain = "-"

    if "<" in from_header and "@" in from_header:
        display_name = from_header.split("<")[0].strip().strip('"')
        email_part = from_header.split("<")[1].split(">")[0]
        domain = email_part.split("@")[1].lower()

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

    return data

# ---------------- FETCH WITH UID LOGIC ----------------

def fetch_emails(start_date, end_date, mailbox="inbox",
                 use_uid_since=False, last_uid=None, batch_id=0):

    results = []
    s = start_date.strftime("%d-%b-%Y")
    e = (end_date + datetime.timedelta(days=1)).strftime("%d-%b-%Y")

    new_last_uid = last_uid

    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(email_input, password_input)
    imap.select(mailbox)

    if mailbox == "inbox" and use_uid_since and last_uid:
        criteria = f'(UID {int(last_uid)+1}:* SINCE {s} BEFORE {e})'
    else:
        criteria = f'(SINCE {s} BEFORE {e})'

    status, data = imap.uid('search', None, criteria)
    uids = data[0].split()

    for uid in uids:
        uid_decoded = uid.decode()

        _, msg_data = imap.uid('fetch', uid, '(BODY.PEEK[HEADER])')

        for part in msg_data:
            if isinstance(part, tuple):
                msg = email.message_from_bytes(part[1])
                d = parse_email_message(msg, batch_id)
                d["Mailbox"] = "Inbox" if mailbox == "inbox" else "Spam"
                results.append(d)

        if mailbox == "inbox":
            new_last_uid = max(new_last_uid, uid_decoded) if new_last_uid else uid_decoded

    imap.logout()
    return pd.DataFrame(results, columns=DF_COLS), new_last_uid

# ---------------- FETCH BUTTON ----------------

if st.button("📥 Fetch Emails"):

    st.session_state.batch_counter += 1
    current_batch = st.session_state.batch_counter

    use_uid_fetch = not st.session_state.df.empty and st.session_state.last_uid is not None

    inbox_df, new_uid = fetch_emails(
        START_DATE, END_DATE,
        "inbox",
        use_uid_since=use_uid_fetch,
        last_uid=st.session_state.last_uid,
        batch_id=current_batch
    )

    spam_df, _ = fetch_emails(
        START_DATE, END_DATE,
        "[Gmail]/Spam",
        batch_id=current_batch
    )

    df_new = pd.concat([inbox_df, spam_df], ignore_index=True)

    if not st.session_state.df.empty:
        seen = set(st.session_state.df["Message-ID"])
        df_new = df_new[~df_new["Message-ID"].isin(seen)]

    st.session_state.df = pd.concat([df_new, st.session_state.df], ignore_index=True)
    st.session_state.last_uid = new_uid

    st.success(f"Batch #{current_batch} fetched. New emails: {len(df_new)}")

# ---------------- STYLING ----------------

BATCH_COLORS = ["#E3F2FD", "#FFF9C4", "#E8F5E9", "#F3E5F5", "#FFE0B2"]

def highlight_rows(row):
    if row["SPF"] != "pass" or row["DKIM"] != "pass" or row["DMARC"] != "pass":
        return ["background-color: rgba(255,0,0,0.25)"] * len(row)

    batch_id = row["Batch_ID"]
    if batch_id:
        color = BATCH_COLORS[(batch_id - 1) % len(BATCH_COLORS)]
        return [f"background-color: {color}"] * len(row)

    return [""] * len(row)

# ---------------- DISPLAY MAIN ----------------

if not st.session_state.df.empty:

    display_cols = ["Subject", "Date", "From", "Domain",
                    "SPF", "DKIM", "DMARC",
                    "Type", "Mailbox", "Batch_ID"]

    display_df = st.session_state.df[display_cols].copy()
    display_df.index += 1

    styled = display_df.style.apply(highlight_rows, axis=1)

    st.subheader("📬 Processed Emails")
    st.dataframe(styled, use_container_width=True,
                 column_config={"Batch_ID": None})

# ---------------- FAILED AUTH TABLE ----------------

failed_df = st.session_state.df[
    (st.session_state.df["SPF"] != "pass") |
    (st.session_state.df["DKIM"] != "pass") |
    (st.session_state.df["DMARC"] != "pass")
]

if not failed_df.empty:
    failed_cols = [
        "Subject", "Date", "From",
        "Domain", "SPF", "DKIM", "DMARC",
        "Type", "Sub ID"
    ]
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

        selected_domains = [d.strip().lower() for d in domain_input.splitlines()]
        results = []

        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_input, password_input)
        imap.select("inbox")

        for _, row in st.session_state.df.iterrows():

            if not any(d in row["Domain"] for d in selected_domains):
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

                # ---- LIST-UNSUB HEADER ONLY ----
                list_unsub = "-"
                lu_headers = msg.get_all("List-Unsubscribe", [])
                if lu_headers:
                    combined = " ".join(lu_headers)
                    urls = re.findall(r'https?://[^\s,<>]+', combined)
                    if urls:
                        list_unsub = urls[0]

                body = ""
                if msg.is_multipart():
                    for p in msg.walk():
                        if p.get_content_type() == "text/html":
                            body_bytes = p.get_payload(decode=True)
                            body = body_bytes.decode(errors="ignore")
                            break

                if not body:
                    continue

                # Clean quoted-printable artifacts
                body = body.replace("=3D", "=")
                body = body.replace("=\r\n", "")
                body = body.replace("=\n", "")

                # Extract A and IMG
                a_links = re.findall(r'<a[^>]+href=["\'](https?://[^"\']+)["\']', body, re.I)
                img_links = re.findall(r'https?://[^\s"\'<>]+\.(?:jpg|jpeg|png|gif|svg)(?:\?[^\s"\']*)?', body, re.I)

                a_links = [l for l in a_links if any(d in l.lower() for d in selected_domains)]
                img_links = [l for l in img_links if any(d in l.lower() for d in selected_domains)]

                unsub = "-"
                for link in a_links:
                    if any(k in link.lower() for k in
                           ["preferences","manage","dropout","rmv","checkout",
                            "opt","optout","remove","unsub"]):
                        unsub = link
                        break

                logo = img_links[0] if img_links else "-"
                pixel = img_links[1] if len(img_links) > 1 else "-"

                results.append({
                    "Subject": row["Subject"],
                    "Date": row["Date"],
                    "From": row["From"],
                    "Sender Domain": row["Domain"],
                    "List-Unsubscribe": list_unsub,
                    "Unsubscribe": unsub,
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
