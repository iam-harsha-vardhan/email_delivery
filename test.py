import streamlit as st
import imaplib
import email
import concurrent.futures
import pandas as pd
import datetime
import pytz
import re
import base64
from email.header import decode_header
from email.utils import parsedate_to_datetime

# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="Enterprise Multi-Account Email Monitor",
    layout="wide"
)

st.title("📧 Enterprise Multi-Account Email Monitoring Platform")

# =====================================================
# CONSTANTS
# =====================================================

UID_SCAN_LIMIT = 3000
CHUNK_SIZE = 200
MAX_WORKERS = 15

MAILBOXES = {
    "Inbox": "inbox",
    "Spam": "[Gmail]/Spam"
}

AUTH_PASS = ["pass"]
AUTH_FAIL = [
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror"
]

ID_RE = re.compile(
    r'(GRM-[A-Za-z0-9._-]+|GMFP-[A-Za-z0-9._-]+|GTC-[A-Za-z0-9._-]+|GRTC-[A-Za-z0-9._-]+)',
    re.I
)

# =====================================================
# SESSION STATE
# =====================================================

if "accounts" not in st.session_state:
    st.session_state.accounts = pd.DataFrame([
        {"Email": "", "Password": ""}
    ])

if "emails_df" not in st.session_state:
    st.session_state.emails_df = pd.DataFrame()

if "last_uids" not in st.session_state:
    st.session_state.last_uids = {}

# =====================================================
# HELPERS
# =====================================================


def decode_mime_words(s):
    if not s:
        return ""

    result = ""

    for word, enc in decode_header(s):
        if isinstance(word, bytes):
            try:
                result += word.decode(enc or 'utf-8', errors='ignore')
            except:
                result += word.decode('utf-8', errors='ignore')
        else:
            result += str(word)

    return result.strip()



def format_ist(raw):
    try:
        dt = parsedate_to_datetime(raw)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)

        ist = pytz.timezone("Asia/Kolkata")
        dt_ist = dt.astimezone(ist)

        return dt_ist.strftime("%d-%b-%Y %I:%M %p")

    except:
        return raw



def extract_auth(headers):
    auth = headers.lower()

    data = {
        "SPF": "none",
        "DKIM": "none",
        "DMARC": "none"
    }

    for k in data.keys():
        m = re.search(fr'{k.lower()}=(\w+)', auth, re.I)

        if m:
            data[k] = m.group(1).lower()

    return data



def get_domain(text):
    if not text:
        return "-"

    m = re.search(r'@([A-Za-z0-9.-]+)', text)

    return m.group(1).lower() if m else "-"



def safe_b64(token):
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            pad = token + '=' * (-len(token) % 4)
            return fn(pad).decode('utf-8', errors='ignore')
        except:
            pass

    return ''



def extract_subid(text):
    if not text:
        return '-', '-'

    m = ID_RE.search(text)

    if m:
        sid = m.group(1)
        return sid, map_type(sid)

    tokens = re.split(r'[\s<>()@._:;,\[\]{}]+', text)

    for t in tokens:
        if len(t) < 6:
            continue

        decoded = safe_b64(t)

        if decoded:
            m = ID_RE.search(decoded)

            if m:
                sid = m.group(1)
                return sid, map_type(sid)

    return '-', '-'



def map_type(subid):
    s = subid.lower()

    if s.startswith("grm"):
        return "FPR"

    if s.startswith("gmfp"):
        return "FP"

    if s.startswith("gtc"):
        return "FPTC"

    if s.startswith("grtc"):
        return "FPRTC"

    return "-"

# =====================================================
# FETCH ENGINE
# =====================================================


def fetch_mailbox(user, password, mailbox_name, mailbox_path):

    rows = []

    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(user, password)
        imap.select(mailbox_path)

        status, data = imap.uid('search', None, 'ALL')

        if status != 'OK':
            return pd.DataFrame()

        uids = data[0].split()[-500:]

        for uid in uids:

            uid_s = uid.decode()

            try:
                _, msgd = imap.uid('fetch', uid, '(BODY.PEEK[HEADER])')

                for part in msgd:

                    if not isinstance(part, tuple):
                        continue

                    msg = email.message_from_bytes(part[1])

                    headers = ''.join(
                        f'{k}: {v}\n'
                        for k, v in msg.items()
                    )

                    auth = extract_auth(headers)

                    sid, typ = extract_subid(headers)

                    row = {
                        "UID": uid_s,
                        "Account": user,
                        "Mailbox": mailbox_name,
                        "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
                        "From": decode_mime_words(msg.get("From", "-")),
                        "Domain": get_domain(msg.get("From", "")),
                        "Date": format_ist(msg.get("Date", "")),
                        "Message-ID": decode_mime_words(msg.get("Message-ID", "")),
                        "Sub ID": sid,
                        "Type": typ,
                        "SPF": auth["SPF"],
                        "DKIM": auth["DKIM"],
                        "DMARC": auth["DMARC"]
                    }

                    row["Auth Result"] = (
                        "PASS"
                        if (
                            row["SPF"] == "pass"
                            and row["DKIM"] == "pass"
                            and row["DMARC"] == "pass"
                        )
                        else "FAIL"
                    )

                    rows.append(row)

            except:
                pass

        imap.logout()

    except Exception as e:
        st.error(f"{user}: {e}")

    return pd.DataFrame(rows)

# =====================================================
# ACCOUNT UI
# =====================================================

st.subheader("📋 Gmail Accounts")

accounts_df = st.data_editor(
    st.session_state.accounts,
    num_rows="dynamic",
    use_container_width=True,
    hide_index=True
)

st.session_state.accounts = accounts_df

# =====================================================
# FILTERS
# =====================================================

st.subheader("🎛 Enterprise Filters")

f1, f2, f3, f4 = st.columns(4)

with f1:
    selected_mailboxes = st.multiselect(
        "Mailbox",
        ["Inbox", "Spam"],
        default=["Inbox", "Spam"]
    )

with f2:
    selected_auth = st.multiselect(
        "Auth Result",
        ["PASS", "FAIL"],
        default=["PASS", "FAIL"]
    )

with f3:
    domain_filter = st.text_input("Domain Filter")

with f4:
    subid_filter = st.text_input("Sub ID Filter")

# =====================================================
# FETCH BUTTON
# =====================================================

if st.button("📥 Fetch Emails"):

    frames = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        futures = []

        for _, row in accounts_df.iterrows():

            user = str(row["Email"]).strip()
            password = str(row["Password"]).strip()

            if not user or not password:
                continue

            for mailbox_name, mailbox_path in MAILBOXES.items():

                futures.append(
                    executor.submit(
                        fetch_mailbox,
                        user,
                        password,
                        mailbox_name,
                        mailbox_path
                    )
                )

        for future in concurrent.futures.as_completed(futures):
            df = future.result()

            if not df.empty:
                frames.append(df)

    if frames:
        st.session_state.emails_df = pd.concat(frames, ignore_index=True)

# =====================================================
# DISPLAY
# =====================================================

if not st.session_state.emails_df.empty:

    df = st.session_state.emails_df.copy()

    if selected_mailboxes:
        df = df[df["Mailbox"].isin(selected_mailboxes)]

    if selected_auth:
        df = df[df["Auth Result"].isin(selected_auth)]

    if domain_filter:
        df = df[
            df["Domain"]
            .str.contains(domain_filter, case=False, na=False)
        ]

    if subid_filter:
        df = df[
            df["Sub ID"]
            .str.contains(subid_filter, case=False, na=False)
        ]

    # ==========================================
    # METRICS
    # ==========================================

    total = len(df)

    passed = len(df[df["Auth Result"] == "PASS"])

    failed = len(df[df["Auth Result"] == "FAIL"])

    spam = len(df[df["Mailbox"] == "Spam"])

    inbox = len(df[df["Mailbox"] == "Inbox"])

    m1, m2, m3, m4, m5 = st.columns(5)

    m1.metric("Total", total)
    m2.metric("Passed", passed)
    m3.metric("Failed", failed)
    m4.metric("Inbox", inbox)
    m5.metric("Spam", spam)

    # ==========================================
    # FAILED EMAILS
    # ==========================================

    failed_df = df[df["Auth Result"] == "FAIL"]

    if not failed_df.empty:
        st.subheader("❌ Failed Emails")
        st.dataframe(failed_df, use_container_width=True)

    # ==========================================
    # MAIN TABLE
    # ==========================================

    st.subheader("📬 Email Intelligence Table")

    st.dataframe(df, use_container_width=True)

    # ==========================================
    # EXPORTS
    # ==========================================

    csv = df.to_csv(index=False).encode('utf-8')

    st.download_button(
        "⬇ Download CSV",
        csv,
        file_name="enterprise_email_monitor.csv",
        mime="text/csv"
    )
