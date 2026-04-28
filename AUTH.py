import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
import datetime
import pandas as pd
import re
import base64
import concurrent.futures

# =====================================================
# PAGE
# =====================================================
st.set_page_config(page_title="Enterprise Email Auth Checker", layout="wide")
st.title("📧 Enterprise Email Authentication Checker")

# =====================================================
# CONSTANTS
# =====================================================
DF_COLS = [
    "Subject", "Date", "Domain",
    "SPF", "DKIM", "DMARC",
    "Type", "Sub ID",
    "Mailbox", "Message-ID",
    "Batch_ID"
]

ID_RE = re.compile(
    r'(GRM-[A-Za-z0-9._-]+|GMFP-[A-Za-z0-9._-]+|GTC-[A-Za-z0-9._-]+|GRTC-[A-Za-z0-9._-]+)',
    re.I
)

# =====================================================
# SESSION
# =====================================================
if "df" not in st.session_state:
    st.session_state.df = pd.DataFrame(columns=DF_COLS)

if "spam_df" not in st.session_state:
    st.session_state.spam_df = pd.DataFrame(columns=DF_COLS)

if "last_uid" not in st.session_state:
    st.session_state.last_uid = None

if "batch_counter" not in st.session_state:
    st.session_state.batch_counter = 0

today = datetime.date.today()

if "fetch_dates" not in st.session_state:
    st.session_state.fetch_dates = (today, today)

# =====================================================
# UI
# =====================================================
with st.container():
    c1, c2, c3, c4 = st.columns([3, 3, 2, 1])

    with c1:
        gmail_user = st.text_input("📧 Gmail Address")

    with c2:
        gmail_pass = st.text_input("🔐 App Password", type="password")

    with c3:
        date_range = st.date_input(
            "Select Date Range",
            value=st.session_state.fetch_dates,
            max_value=today
        )

        if isinstance(date_range, tuple):
            start_date, end_date = date_range
        else:
            start_date = date_range
            end_date = date_range

        st.session_state.fetch_dates = (start_date, end_date)

    with c4:
        st.markdown("###")
        if st.button("🔁"):
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()

if not gmail_user or not gmail_pass:
    st.warning("Enter Gmail Address and App Password")
    st.stop()

# =====================================================
# HELPERS
# =====================================================
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
            pass
    return out.strip()


def format_date_ist(raw):
    try:
        dt = parsedate_to_datetime(raw)
        ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
        dt = dt.astimezone(ist)
        return dt.strftime("%d-%b-%Y %I:%M %p")
    except:
        return raw


def get_type(subid):
    x = subid.lower()

    if x.startswith("grm"):
        return "FPR"
    elif x.startswith("gmfp"):
        return "FP"
    elif x.startswith("gtc"):
        return "FPTC"
    elif x.startswith("grtc"):
        return "FPRTC"
    return "-"


def safe_b64_decode(token):
    token = token.strip()

    if not token:
        return ""

    try:
        pad = token + "=" * (-len(token) % 4)
        return base64.b64decode(pad).decode("utf-8", errors="ignore")
    except:
        pass

    try:
        pad = token + "=" * (-len(token) % 4)
        return base64.urlsafe_b64decode(pad).decode("utf-8", errors="ignore")
    except:
        pass

    return ""


def extract_subid_advanced(raw_text):
    if not raw_text:
        return "-", "-"

    # direct hit
    m = ID_RE.search(raw_text)
    if m:
        sid = m.group(1)
        return sid, get_type(sid)

    # split tokens
    tokens = re.split(r'[\s<>()@._:;,\[\]{}]+', raw_text)

    for token in tokens:
        if len(token) < 6:
            continue

        dec = safe_b64_decode(token)

        if dec:
            m = ID_RE.search(dec)
            if m:
                sid = m.group(1)
                return sid, get_type(sid)

            # double decode
            dec2 = safe_b64_decode(dec)
            if dec2:
                m2 = ID_RE.search(dec2)
                if m2:
                    sid = m2.group(1)
                    return sid, get_type(sid)

    return "-", "-"


def parse_email(msg, batch_id):
    raw_date = msg.get("Date", "")

    data = {
        "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
        "Date": format_date_ist(raw_date),
        "Domain": "-",
        "SPF": "-",
        "DKIM": "-",
        "DMARC": "-",
        "Type": "-",
        "Sub ID": "-",
        "Mailbox": "-",
        "Message-ID": decode_mime_words(msg.get("Message-ID", "")),
        "Batch_ID": batch_id
    }

    headers = "".join(f"{k}: {v}\n" for k, v in msg.items())

    # domain
    m = re.search(r'smtp.mailfrom=([\w\.-]+)', headers, re.I)
    if m:
        data["Domain"] = m.group(1).lower()
    else:
        frm = msg.get("From", "")
        m2 = re.search(r'@([\w\.-]+)', frm)
        if m2:
            data["Domain"] = m2.group(1).lower()

    # auth
    m = re.search(r'spf=(\w+)', headers, re.I)
    if m:
        data["SPF"] = m.group(1).lower()

    m = re.search(r'dkim=(\w+)', headers, re.I)
    if m:
        data["DKIM"] = m.group(1).lower()

    m = re.search(r'dmarc=(\w+)', headers, re.I)
    if m:
        data["DMARC"] = m.group(1).lower()

    # subid
    sid, typ = extract_subid_advanced(headers)
    data["Sub ID"] = sid
    data["Type"] = typ

    return data

# =====================================================
# FETCH
# =====================================================
def fetch_mailbox(mailbox, start_date, end_date, use_uid=False, last_uid=None, batch_id=0):
    rows = []
    new_last_uid = last_uid

    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(gmail_user, gmail_pass)
        imap.select(mailbox)

        s = start_date.strftime("%d-%b-%Y")
        e = (end_date + datetime.timedelta(days=1)).strftime("%d-%b-%Y")

        if mailbox == "inbox" and use_uid and last_uid:
            criteria = f'(UID {int(last_uid)+1}:* SINCE {s} BEFORE {e})'
        else:
            criteria = f'(SINCE {s} BEFORE {e})'

        _, data = imap.uid("search", None, criteria)
        uids = data[0].split()

        for uid in uids:
            uid_str = uid.decode()

            _, msg_data = imap.uid("fetch", uid, "(BODY.PEEK[HEADER])")

            for item in msg_data:
                if isinstance(item, tuple):
                    msg = email.message_from_bytes(item[1])
                    row = parse_email(msg, batch_id)
                    row["Mailbox"] = "Inbox" if mailbox == "inbox" else "Spam"
                    rows.append(row)

            if mailbox == "inbox":
                if not new_last_uid:
                    new_last_uid = uid_str
                else:
                    new_last_uid = str(max(int(new_last_uid), int(uid_str)))

        imap.logout()

    except Exception as e:
        st.error(f"{mailbox}: {e}")

    return pd.DataFrame(rows, columns=DF_COLS), new_last_uid


def merge_df(new_df, old_df):
    if old_df.empty:
        return new_df

    seen = set(old_df["Message-ID"].dropna())
    new_df = new_df[~new_df["Message-ID"].isin(seen)]

    out = pd.concat([new_df, old_df], ignore_index=True)
    out = out.sort_values("Batch_ID", ascending=False, ignore_index=True)

    return out

# =====================================================
# STYLE
# =====================================================
def style_rows(row):
    failed = (
        row["SPF"] != "pass" or
        row["DKIM"] != "pass" or
        row["DMARC"] != "pass"
    )

    if failed:
        return ['background-color: rgba(255,0,0,0.22)'] * len(row)

    return [''] * len(row)

# =====================================================
# BUTTONS
# =====================================================
b1, b2 = st.columns(2)

with b1:
    if st.button("📥 Fetch Emails"):
        st.session_state.batch_counter += 1
        batch = st.session_state.batch_counter

        use_uid = (
            not st.session_state.df.empty and
            st.session_state.last_uid is not None
        )

        with st.spinner("Fetching Inbox + Spam using Multi Threading..."):

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as exe:
                f1 = exe.submit(
                    fetch_mailbox,
                    "inbox",
                    start_date,
                    end_date,
                    use_uid,
                    st.session_state.last_uid,
                    batch
                )

                f2 = exe.submit(
                    fetch_mailbox,
                    "[Gmail]/Spam",
                    start_date,
                    end_date,
                    False,
                    None,
                    batch
                )

                inbox_df, new_uid = f1.result()
                spam_df, _ = f2.result()

            combined = pd.concat([inbox_df, spam_df], ignore_index=True)

            st.session_state.df = merge_df(combined, st.session_state.df)
            st.session_state.last_uid = new_uid

            st.success(f"Fetched {len(combined)} Emails")

with b2:
    if st.button("🗑️ Fetch Spam Only"):
        st.session_state.batch_counter += 1
        batch = st.session_state.batch_counter

        spam_df, _ = fetch_mailbox(
            "[Gmail]/Spam",
            start_date,
            end_date,
            False,
            None,
            batch
        )

        st.session_state.spam_df = merge_df(
            spam_df,
            st.session_state.spam_df
        )

        st.success(f"Fetched {len(spam_df)} Spam Emails")

# =====================================================
# PROCESSED EMAILS
# =====================================================
st.subheader("📬 Processed Emails")

if not st.session_state.df.empty:
    show_cols = [
        "Subject", "Date", "Domain",
        "SPF", "DKIM", "DMARC",
        "Type", "Sub ID",
        "Mailbox", "Batch_ID"
    ]

    st.dataframe(
    st.session_state.df[show_cols].style.apply(style_rows, axis=1),
    use_container_width=True,
    column_config={
        "Batch_ID": None,
        "Sub ID": None
    })

# =====================================================
# FAILED AUTH
# =====================================================
if not st.session_state.df.empty:
    failed = st.session_state.df[
        (st.session_state.df["SPF"] != "pass") |
        (st.session_state.df["DKIM"] != "pass") |
        (st.session_state.df["DMARC"] != "pass")
    ].reset_index(drop=True)

    if not failed.empty:
        st.subheader("❌ Failed Auth Emails")

        show_cols = [
            "Subject", "Domain",
            "SPF", "DKIM", "DMARC",
            "Type", "Sub ID", "Mailbox"
        ]

        st.dataframe(
            failed[show_cols].style.apply(style_rows, axis=1),
            use_container_width=True
        )

        st.info(f"Total Failed Rows: {len(failed)}")

# =====================================================
# SPAM
# =====================================================
if not st.session_state.spam_df.empty:
    st.subheader("🚫 Spam Emails")

    show_cols = [
        "Subject", "Date", "Domain",
        "Type", "Sub ID",
        "Mailbox", "Batch_ID"
    ]

    st.dataframe(
        st.session_state.spam_df[show_cols],
        use_container_width=True,
        column_config={"Batch_ID": None}
    )
