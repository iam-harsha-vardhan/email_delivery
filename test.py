import streamlit as st
import imaplib
import email
import datetime
import pandas as pd
import pytz
import re
import base64
import concurrent.futures

from email.header import decode_header
from email.utils import parsedate_to_datetime

# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="Enterprise Multi Account Email Monitor",
    layout="wide"
)

st.title("📧 Enterprise Multi Account Email Monitoring Platform")

# =========================================================
# CONSTANTS
# =========================================================

UID_SCAN_LIMIT = 3000
CHUNK_SIZE = 200
MAX_WORKERS = 10

MAILBOXES = {
    "Inbox": "inbox",
    "Spam": "[Gmail]/Spam"
}

ID_RE = re.compile(
r'\b(GRM-[A-Za-z0-9.\-]+|GMFP-[A-Za-z0-9.\-]+|GTC-[A-Za-z0-9.\-]+|GRTC-[A-Za-z0-9.\-]+)\b',
re.I
)

# =========================================================
# SESSION STATE
# =========================================================

if "accounts_df" not in st.session_state:
    st.session_state.accounts_df = pd.DataFrame([
        {"Email": "", "Password": ""}
    ])

if "emails_df" not in st.session_state:
    st.session_state.emails_df = pd.DataFrame()

if "last_uid_map" not in st.session_state:
    st.session_state.last_uid_map = {}

# =========================================================
# HELPERS
# =========================================================

def decode_mime_words(s):

    if not s:
        return ""

    decoded = ""

    for word, enc in decode_header(s):

        if isinstance(word, bytes):

            try:
                decoded += word.decode(
                    enc or 'utf-8',
                    errors='ignore'
                )

            except:
                decoded += word.decode(
                    'utf-8',
                    errors='ignore'
                )

        else:
            decoded += word

    return decoded.strip()

# =========================================================

def format_date_to_ist(raw_date):

    if not raw_date:
        return "-"

    try:
        dt = parsedate_to_datetime(raw_date)

        if dt.tzinfo is None:
            dt = dt.replace(
                tzinfo=datetime.timezone.utc
            )

        ist = pytz.timezone("Asia/Kolkata")

        dt_ist = dt.astimezone(ist)

        return dt_ist.strftime(
            "%d-%b-%Y %I:%M %p"
        )

    except:
        return raw_date

# =========================================================

def extract_domain(address):

    if not address:
        return "-"

    m = re.search(
        r'@([\w\.-]+)',
        address
    )

    return m.group(1).lower() if m else "-"

# =========================================================
# AUTH EXTRACTION
# =========================================================

def extract_auth_results(msg):

    auth = (
        msg.get("Authentication-Results", "")
        or " ".join(
            f"{h}: {v}"
            for h, v in msg.items()
        )
    )

    spf = dkim = dmarc = 'none'

    m_spf = re.search(
        r'spf=(\w+)',
        auth,
        re.I
    )

    m_dkim = re.search(
        r'dkim=(\w+)',
        auth,
        re.I
    )

    m_dmarc = re.search(
        r'dmarc=(\w+)',
        auth,
        re.I
    )

    if m_spf:
        spf = m_spf.group(1).lower()

    if m_dkim:
        dkim = m_dkim.group(1).lower()

    if m_dmarc:
        dmarc = m_dmarc.group(1).lower()

    return spf, dkim, dmarc

# =========================================================
# SUBID ENGINE (YOUR BEST VERSION)
# =========================================================

def map_id_to_type(sub_id):

    if not sub_id:
        return "-"

    lid = sub_id.lower()

    if lid.startswith('grm'):
        return 'FPR'

    if lid.startswith('gmfp'):
        return 'FP'

    if lid.startswith('gtc'):
        return 'FPTC'

    if lid.startswith('grtc'):
        return 'FPRTC'

    return "-"

# =========================================================

def try_base64_variants(s):

    if not s or len(s) < 4:
        return None

    s = s.strip()

    if s.startswith('<') and s.endswith('>'):
        s = s[1:-1]

    for decoder in (
        base64.b64decode,
        base64.urlsafe_b64decode
    ):

        for pad in range(0, 4):

            try:

                cand = s + ('=' * pad)

                decoded = decoder(cand)

                try:
                    text = decoded.decode(
                        'utf-8',
                        errors='ignore'
                    )

                except:
                    continue

                if text and text.strip():
                    return text

            except:
                continue

    return None

# =========================================================

def find_subid_in_text(txt):

    if not txt:
        return None

    m = ID_RE.search(txt)

    return m.group(1) if m else None

# =========================================================

def extract_subid_from_msg(msg):

    msg_id_raw = decode_mime_words(
        msg.get("Message-ID", "")
        or msg.get("Message-Id", "")
        or ""
    )

    prefixes = (
        "GRM-",
        "GMFP-",
        "GTC-",
        "GRTC-"
    )

    if msg_id_raw:

        tokens = re.split(
            r'[._<>\s@]+',
            msg_id_raw
        )

        for token in tokens:

            if not token or len(token) < 6:
                continue

            if token.upper().startswith(prefixes):

                return (
                    token.strip(),
                    map_id_to_type(token.strip())
                )

            decoded = try_base64_variants(token)

            if decoded:

                decoded = decoded.strip()

                if decoded.upper().startswith(prefixes):

                    return (
                        decoded,
                        map_id_to_type(decoded)
                    )

                m = find_subid_in_text(decoded)

                if m:

                    return (
                        m,
                        map_id_to_type(m)
                    )

    headers_str = " ".join(
        f"{h}:{v}"
        for h, v in msg.items()
    )

    m = find_subid_in_text(headers_str)

    if m:

        return (
            m,
            map_id_to_type(m)
        )

    return "-", "-"

# =========================================================
# FETCH ENGINE
# =========================================================

def fetch_emails(
    user,
    password,
    mailbox_name,
    mailbox_path,
    fetch_mode,
    fetch_n
):

    rows = []

    try:

        imap = imaplib.IMAP4_SSL(
            "imap.gmail.com"
        )

        imap.login(user, password)

        imap.select(mailbox_path)

        # ============================================
        # FETCH MODES
        # ============================================

        if fetch_mode == "Last N Emails":

            status, data = imap.uid(
                'search',
                None,
                'ALL'
            )

            uids = data[0].split()[-int(fetch_n):]

        elif fetch_mode == "Last N Hours":

            status, data = imap.uid(
                'search',
                None,
                'ALL'
            )

            all_uids = data[0].split()

            uids = all_uids[-UID_SCAN_LIMIT:]

        elif fetch_mode == "Last N Minutes":

            status, data = imap.uid(
                'search',
                None,
                'ALL'
            )

            all_uids = data[0].split()

            uids = all_uids[-UID_SCAN_LIMIT:]

        elif fetch_mode == "Last N Days":

            since_date = (
                datetime.datetime.now()
                - datetime.timedelta(days=int(fetch_n))
            ).strftime("%d-%b-%Y")

            status, data = imap.uid(
                'search',
                None,
                f'(SINCE "{since_date}")'
            )

            uids = data[0].split()

        else:

            status, data = imap.uid(
                'search',
                None,
                'ALL'
            )

            uids = data[0].split()[-100:]

        # ============================================
        # FETCH EMAILS
        # ============================================

        for uid in uids:

            try:

                uid_s = uid.decode()

                res, msg_data = imap.uid(
                    'fetch',
                    uid,
                    '(BODY.PEEK[HEADER])'
                )

                for part in msg_data:

                    if not isinstance(part, tuple):
                        continue

                    msg = email.message_from_bytes(
                        part[1]
                    )

                    subject = decode_mime_words(
                        msg.get("Subject", "")
                    )

                    from_h = decode_mime_words(
                        msg.get("From", "")
                    )

                    domain = extract_domain(
                        from_h
                    )

                    spf, dkim, dmarc = (
                        extract_auth_results(msg)
                    )

                    subid, sub_type = (
                        extract_subid_from_msg(msg)
                    )

                    auth_result = (
                        "PASS"
                        if (
                            spf == "pass"
                            and dkim == "pass"
                            and dmarc == "pass"
                        )
                        else "FAIL"
                    )

                    rows.append({

                        "UID": uid_s,

                        "Account": user,

                        "Mailbox": mailbox_name,

                        "Subject": subject,

                        "From": from_h,

                        "Domain": domain,

                        "SPF": spf,

                        "DKIM": dkim,

                        "DMARC": dmarc,

                        "Auth Result": auth_result,

                        "Sub ID": subid,

                        "Type": sub_type,

                        "Message-ID":
                            decode_mime_words(
                                msg.get(
                                    "Message-ID",
                                    ""
                                )
                            ),

                        "Date":
                            format_date_to_ist(
                                msg.get(
                                    "Date",
                                    ""
                                )
                            )
                    })

            except:
                continue

        imap.logout()

    except Exception as e:

        st.error(f"{user}: {e}")

    return pd.DataFrame(rows)

# =========================================================
# ACCOUNT UI
# =========================================================

st.subheader("📋 Multi Account Credentials")

accounts_df = st.data_editor(
    st.session_state.accounts_df,
    num_rows="dynamic",
    use_container_width=True,
    hide_index=True
)

st.session_state.accounts_df = accounts_df

# =========================================================
# FETCH CONTROLS
# =========================================================

st.subheader("⚙ Fetch Controls")

c1, c2, c3, c4 = st.columns(4)

with c1:

    fetch_mode = st.selectbox(
        "Fetch Mode",
        [
            "Last N Emails",
            "Last N Hours",
            "Last N Minutes",
            "Last N Days"
        ]
    )

with c2:

    fetch_n = st.number_input(
        "Value",
        min_value=1,
        value=10
    )

with c3:

    mailbox_selection = st.multiselect(
        "Mailbox",
        ["Inbox", "Spam"],
        default=["Inbox", "Spam"]
    )

with c4:

    auth_filter = st.multiselect(
        "Auth Filter",
        ["PASS", "FAIL"],
        default=["PASS", "FAIL"]
    )

# =========================================================
# FETCH BUTTON
# =========================================================

if st.button("📥 Fetch Emails"):

    frames = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = []

        for _, row in accounts_df.iterrows():

            user = str(
                row["Email"]
            ).strip()

            password = str(
                row["Password"]
            ).strip()

            if not user or not password:
                continue

            for mb in mailbox_selection:

                futures.append(

                    executor.submit(
                        fetch_emails,
                        user,
                        password,
                        mb,
                        MAILBOXES[mb],
                        fetch_mode,
                        fetch_n
                    )
                )

        for future in concurrent.futures.as_completed(
            futures
        ):

            df = future.result()

            if not df.empty:
                frames.append(df)

    if frames:

        st.session_state.emails_df = pd.concat(
            frames,
            ignore_index=True
        )

# =========================================================
# DISPLAY
# =========================================================

if not st.session_state.emails_df.empty:

    df = st.session_state.emails_df.copy()

    # =============================================
    # FILTERS
    # =============================================

    if mailbox_selection:

        df = df[
            df["Mailbox"].isin(
                mailbox_selection
            )
        ]

    if auth_filter:

        df = df[
            df["Auth Result"].isin(
                auth_filter
            )
        ]

    # =============================================
    # METRICS
    # =============================================

    total = len(df)

    passed = len(
        df[df["Auth Result"] == "PASS"]
    )

    failed = len(
        df[df["Auth Result"] == "FAIL"]
    )

    inbox = len(
        df[df["Mailbox"] == "Inbox"]
    )

    spam = len(
        df[df["Mailbox"] == "Spam"]
    )

    m1, m2, m3, m4, m5 = st.columns(5)

    m1.metric("Total", total)
    m2.metric("Passed", passed)
    m3.metric("Failed", failed)
    m4.metric("Inbox", inbox)
    m5.metric("Spam", spam)

    # =============================================
    # FAILED EMAILS
    # =============================================

    failed_df = df[
        df["Auth Result"] == "FAIL"
    ]

    if not failed_df.empty:

        st.subheader("❌ Failed Emails")

        st.dataframe(
            failed_df,
            use_container_width=True
        )

    # =============================================
    # MAIN TABLE
    # =============================================

    st.subheader(
        "📬 Enterprise Email Intelligence Table"
    )

    st.dataframe(
        df.sort_values(
            by="Date",
            ascending=False
        ),
        use_container_width=True
    )

    # =============================================
    # EXPORT
    # =============================================

    csv = df.to_csv(
        index=False
    ).encode('utf-8')

    st.download_button(
        "⬇ Download CSV",
        csv,
        file_name="enterprise_email_monitor.csv",
        mime="text/csv"
    )

# =========================================================
# CLEAR
# =========================================================

if st.button("🗑 Clear Data"):

    st.session_state.emails_df = pd.DataFrame()

    st.success("Cleared")
