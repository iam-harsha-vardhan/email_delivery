import streamlit as st
import imaplib
import email
import datetime
import re
import base64
import concurrent.futures

import pandas as pd

from email.header import decode_header
from email.utils import parsedate_to_datetime


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title='Enterprise Email Auth Checker',
    layout='wide'
)

st.title('📧 Enterprise Email Authentication Checker')


# ============================================================
# COLUMNS
# ============================================================

DF_COLS = [
    "Subject",
    "Date",
    "Domain",
    "SPF",
    "DKIM",
    "DMARC",
    "Type",
    "Blast/Sub ID",
    "Mailbox",
    "Message-ID",
    "Batch_ID"
]


# ============================================================
# SUB-ID PATTERN
# ============================================================

ID_RE = re.compile(
    r'(GRM-[A-Za-z0-9._-]+|'
    r'GMFP-[A-Za-z0-9._-]+|'
    r'GTC-[A-Za-z0-9._-]+|'
    r'GRTC-[A-Za-z0-9._-]+)',
    re.I
)


# ============================================================
# BLAST-ID PATTERN
#
# Examples:
#
# 67159853o0qs
# 07951351kek7
# 30638613bap5
# 748499244e53
# 001038745yhf
#
# General observed structure:
# - exactly 12 characters
# - first character must be a digit
# - remaining 11 characters are alphanumeric
# ============================================================

BLAST_ID_RE = re.compile(
    r'^[0-9][A-Za-z0-9]{11}$'
)


# ============================================================
# SESSION STATE
# ============================================================

for k, v in {
    'df': pd.DataFrame(columns=DF_COLS),
    'spam_df': pd.DataFrame(columns=DF_COLS),
    'last_uid': None,
    'batch_counter': 0,
    'fetch_dates': (
        datetime.date.today(),
        datetime.date.today()
    )
}.items():

    if k not in st.session_state:
        st.session_state[k] = v


# ============================================================
# MIME WORD DECODER
# ============================================================

def decode_mime_words(s):

    if not s:
        return ''

    out = ''

    for part, enc in decode_header(s):

        try:

            if isinstance(part, bytes):

                out += part.decode(
                    enc or 'utf-8',
                    errors='ignore'
                )

            else:

                out += str(part)

        except Exception:

            pass

    return out.strip()


# ============================================================
# DATE FORMAT
# ============================================================

def format_date_ist(raw):

    try:

        dt = parsedate_to_datetime(raw)

        ist = datetime.timezone(
            datetime.timedelta(
                hours=5,
                minutes=30
            )
        )

        return dt.astimezone(ist).strftime(
            '%d-%b-%Y %I:%M %p'
        )

    except Exception:

        return raw or '-'


# ============================================================
# EMAIL TYPE
# ============================================================

def get_type(s):

    x = s.lower()

    if x.startswith('grm'):
        return 'FPR'

    if x.startswith('gmfp'):
        return 'FP'

    if x.startswith('gtc'):
        return 'FPTC'

    if x.startswith('grtc'):
        return 'FPRTC'

    return '-'


# ============================================================
# SAFE BASE64 DECODER
# ============================================================

def safe_b64(token):

    if not token:
        return ''

    token = token.strip()

    # Remove whitespace introduced by wrapping
    token = re.sub(
        r'\s+',
        '',
        token
    )

    variants = [
        token,
        token.replace(
            '-',
            '+'
        ).replace(
            '_',
            '/'
        )
    ]

    for value in variants:

        try:

            padding = '=' * (
                -len(value) % 4
            )

            decoded = base64.b64decode(
                value + padding,
                validate=False
            )

            text = decoded.decode(
                'utf-8',
                errors='ignore'
            )

            if text:

                return text

        except Exception:

            pass

    return ''


# ============================================================
# SUB-ID EXTRACTION
# ============================================================

def extract_subid(text):

    if not text:

        return '-', '-'

    # --------------------------------------------------------
    # Direct Sub ID
    # --------------------------------------------------------

    m = ID_RE.search(text)

    if m:

        sid = m.group(1)

        return (
            sid,
            get_type(sid)
        )

    # --------------------------------------------------------
    # Try separated tokens
    # --------------------------------------------------------

    tokens = re.split(
        r'[\s<>()@._:;,\[\]{}]+',
        text
    )

    for token in tokens:

        if len(token) < 6:

            continue

        decoded = safe_b64(token)

        if decoded:

            m = ID_RE.search(
                decoded
            )

            if m:

                sid = m.group(1)

                return (
                    sid,
                    get_type(sid)
                )

    return '-', '-'


# ============================================================
# BLAST-ID VALIDATION
# ============================================================

def is_blast_id(value):

    if not value:

        return False

    value = value.strip()

    return bool(
        BLAST_ID_RE.fullmatch(
            value
        )
    )


# ============================================================
# EXTRACT POSSIBLE BASE64-LIKE TOKENS
#
# We intentionally do NOT assume "_".
# ============================================================

def extract_possible_tokens(text):

    if not text:

        return []

    return re.findall(
        r'[A-Za-z0-9+/_=-]{4,}',
        text
    )


# ============================================================
# FIND BLAST IDS INSIDE TEXT
# ============================================================

def find_blast_ids_in_text(text):

    if not text:

        return []

    found = []

    # --------------------------------------------------------
    # Search token-like sections
    # --------------------------------------------------------

    tokens = extract_possible_tokens(
        text
    )

    for token in tokens:

        # Direct candidate
        if is_blast_id(token):

            value = token.lower()

            if value not in found:

                found.append(value)

        # Decode candidate
        decoded = safe_b64(
            token
        )

        if decoded:

            decoded = decoded.strip()

            # Entire decoded value
            if is_blast_id(decoded):

                value = decoded.lower()

                if value not in found:

                    found.append(value)

            # Blast ID might occur inside
            # a larger decoded string
            for match in re.findall(
                r'(?<![A-Za-z0-9])'
                r'[0-9][A-Za-z0-9]{11}'
                r'(?![A-Za-z0-9])',
                decoded
            ):

                value = match.lower()

                if value not in found:

                    found.append(value)

    # --------------------------------------------------------
    # Also scan complete text directly
    # --------------------------------------------------------

    for match in re.findall(
        r'(?<![A-Za-z0-9])'
        r'[0-9][A-Za-z0-9]{11}'
        r'(?![A-Za-z0-9])',
        text
    ):

        value = match.lower()

        if value not in found:

            found.append(value)

    return found


# ============================================================
# EXTRACT BLAST ID FROM MESSAGE-ID
# ============================================================

def extract_blast_id(message_id):

    if not message_id:

        return '-'

    found = []

    def add(value):

        if not value:

            return

        value = value.strip()

        # Direct complete Blast ID
        if is_blast_id(value):

            value = value.lower()

            if value not in found:

                found.append(value)

        # Search inside text
        for blast in find_blast_ids_in_text(
            value
        ):

            if blast not in found:

                found.append(blast)

    # --------------------------------------------------------
    # 1. Inspect original Message-ID
    # --------------------------------------------------------

    add(message_id)

    # --------------------------------------------------------
    # 2. Inspect ALL candidate tokens
    #
    # No assumption about "_" separator.
    # --------------------------------------------------------

    tokens = extract_possible_tokens(
        message_id
    )

    for token in tokens:

        # Direct candidate
        add(token)

        # Base64 decode
        decoded = safe_b64(
            token
        )

        if decoded:

            add(decoded)

            # Decode another layer if necessary
            nested_tokens = extract_possible_tokens(
                decoded
            )

            for nested in nested_tokens:

                nested_decoded = safe_b64(
                    nested
                )

                if nested_decoded:

                    add(
                        nested_decoded
                    )

    # --------------------------------------------------------
    # 3. Look at pieces separated by common delimiters
    #
    # This is supplementary; "_" is NOT required.
    # --------------------------------------------------------

    pieces = re.split(
        r'[^A-Za-z0-9+/_=-]+',
        message_id
    )

    for piece in pieces:

        if not piece:

            continue

        add(piece)

        decoded = safe_b64(
            piece
        )

        if decoded:

            add(decoded)

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    if found:

        return ', '.join(found)

    return '-'


# ============================================================
# EXTRACT DOMAIN
# ============================================================

def extract_domain(msg, headers):

    # --------------------------------------------------------
    # 1. Authentication-Results → smtp.mailfrom
    # --------------------------------------------------------

    m = re.search(
        r'smtp\.mailfrom='
        r'[A-Za-z0-9._%+-]+@'
        r'([A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        headers,
        re.I
    )

    if m:

        return m.group(1).lower()

    # --------------------------------------------------------
    # 2. Return-Path fallback
    # --------------------------------------------------------

    rp = msg.get(
        'Return-Path',
        ''
    )

    m = re.search(
        r'[A-Za-z0-9._%+-]+@'
        r'([A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        rp,
        re.I
    )

    if m:

        return m.group(1).lower()

    # --------------------------------------------------------
    # 3. From header fallback
    # --------------------------------------------------------

    frm = decode_mime_words(
        msg.get(
            'From',
            ''
        )
    )

    m = re.search(
        r'[A-Za-z0-9._%+-]+@'
        r'([A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        frm,
        re.I
    )

    if m:

        return m.group(1).lower()

    return '-'


# ============================================================
# PARSE EMAIL
# ============================================================

def parse_email(msg, batch):

    headers = ''.join(
        f'{k}: {v}\n'
        for k, v in msg.items()
    )

    # --------------------------------------------------------
    # Existing Sub-ID logic
    # --------------------------------------------------------

    sid, typ = extract_subid(
        headers
    )

    # --------------------------------------------------------
    # Message-ID
    # --------------------------------------------------------

    message_id = decode_mime_words(
        msg.get(
            'Message-ID',
            ''
        )
    )

    # --------------------------------------------------------
    # Blast ID
    # --------------------------------------------------------

    blast_id = extract_blast_id(
        message_id
    )

    # --------------------------------------------------------
    # Choose one identifier
    #
    # Sub ID has priority.
    # Otherwise use Blast ID.
    # --------------------------------------------------------

    if sid != '-':

        identifier = sid

    elif blast_id != '-':

        identifier = blast_id

    else:

        identifier = '-'

    data = {

        'Subject':
            decode_mime_words(
                msg.get(
                    'Subject',
                    'No Subject'
                )
            ),

        'Date':
            format_date_ist(
                msg.get(
                    'Date',
                    ''
                )
            ),

        'Domain':
            extract_domain(
                msg,
                headers
            ),

        'SPF':
            '-',

        'DKIM':
            '-',

        'DMARC':
            '-',

        'Type':
            typ,

        'Blast/Sub ID':
            identifier,

        'Mailbox':
            '-',

        'Message-ID':
            message_id,

        'Batch_ID':
            batch
    }

    # --------------------------------------------------------
    # Authentication Results
    # --------------------------------------------------------

    for key in (
        'SPF',
        'DKIM',
        'DMARC'
    ):

        m = re.search(
            fr'{key.lower()}=(\w+)',
            headers,
            re.I
        )

        if m:

            data[key] = (
                m.group(1).lower()
            )

    return data


# ============================================================
# DYNAMIC COLUMN NAME
# ============================================================

def get_identifier_column_name(df):

    if df.empty:

        return 'Blast/Sub ID'

    values = (
        df['Blast/Sub ID']
        .dropna()
        .astype(str)
        .str.strip()
    )

    values = values[
        values != '-'
    ]

    if values.empty:

        return 'Blast/Sub ID'

    # --------------------------------------------------------
    # Identify Sub IDs
    # --------------------------------------------------------

    subid_mask = values.str.match(
        r'^(GRM|GMFP|GTC|GRTC)-',
        case=False,
        na=False
    )

    subid_count = int(
        subid_mask.sum()
    )

    blast_count = int(
        (~subid_mask).sum()
    )

    if (
        subid_count > 0
        and blast_count == 0
    ):

        return 'Sub ID'

    if (
        blast_count > 0
        and subid_count == 0
    ):

        return 'Blast ID'

    return 'Blast/Sub ID'


# ============================================================
# FETCH MAILBOX
# ============================================================

def fetch_box(
    user,
    pwd,
    mailbox,
    s,
    e,
    use_uid,
    last_uid,
    batch
):

    rows = []

    new_last = last_uid

    imap = imaplib.IMAP4_SSL(
        'imap.gmail.com'
    )

    imap.login(
        user,
        pwd
    )

    imap.select(
        mailbox
    )

    ss = s.strftime(
        '%d-%b-%Y'
    )

    ee = (
        e +
        datetime.timedelta(days=1)
    ).strftime(
        '%d-%b-%Y'
    )

    crit = (
        f'(SINCE {ss} '
        f'BEFORE {ee})'
    )

    # --------------------------------------------------------
    # Incremental Inbox fetch
    # --------------------------------------------------------

    if (
        mailbox == 'inbox'
        and use_uid
        and last_uid
    ):

        crit = (
            f'(UID '
            f'{int(last_uid) + 1}:* '
            f'SINCE {ss} '
            f'BEFORE {ee})'
        )

    _, data = imap.uid(
        'search',
        None,
        crit
    )

    for uid in data[0].split():

        uid_s = uid.decode()

        _, msgd = imap.uid(
            'fetch',
            uid,
            '(BODY.PEEK[HEADER])'
        )

        for part in msgd:

            if isinstance(
                part,
                tuple
            ):

                msg = email.message_from_bytes(
                    part[1]
                )

                r = parse_email(
                    msg,
                    batch
                )

                r['Mailbox'] = (
                    'Inbox'
                    if mailbox == 'inbox'
                    else 'Spam'
                )

                rows.append(r)

        # ----------------------------------------------------
        # Track latest Inbox UID
        # ----------------------------------------------------

        if mailbox == 'inbox':

            new_last = (
                uid_s
                if not new_last
                else str(
                    max(
                        int(new_last),
                        int(uid_s)
                    )
                )
            )

    imap.logout()

    return (
        pd.DataFrame(
            rows,
            columns=DF_COLS
        ),
        new_last
    )


# ============================================================
# MERGE DATAFRAMES
# ============================================================

def merge_df(new, old):

    if old.empty:

        return new

    seen = set(
        old['Message-ID']
        .dropna()
    )

    new = new[
        ~new['Message-ID'].isin(
            seen
        )
    ]

    out = pd.concat(
        [
            new,
            old
        ],
        ignore_index=True
    )

    return out.sort_values(
        'Batch_ID',
        ascending=False
    ).reset_index(
        drop=True
    )


# ============================================================
# ROW STYLING
# ============================================================

def style_rows(row):

    fail = (
        row['SPF'] != 'pass'
        or row['DKIM'] != 'pass'
        or row['DMARC'] != 'pass'
    )

    if fail:

        return [
            'background-color: rgba(255,0,0,0.18)'
        ] * len(row)

    return [
        ''
    ] * len(row)


# ============================================================
# INPUT SECTION
# ============================================================

c1, c2, c3, c4 = st.columns(
    [3, 3, 2, 1]
)

with c1:

    user = st.text_input(
        '📧 Gmail Address'
    )

with c2:

    pwd = st.text_input(
        '🔐 App Password',
        type='password'
    )

with c3:

    dr = st.date_input(
        'Select Date Range',
        value=st.session_state.fetch_dates,
        max_value=datetime.date.today()
    )

    if isinstance(
        dr,
        tuple
    ):

        st.session_state.fetch_dates = dr

    else:

        st.session_state.fetch_dates = (
            dr,
            dr
        )

with c4:

    st.markdown('###')

    if st.button(
        '🔁 Clear'
    ):

        st.session_state.clear()

        st.rerun()


# ============================================================
# LOGIN CHECK
# ============================================================

if not user or not pwd:

    st.warning(
        'Enter Gmail + App Password'
    )

    st.stop()


# ============================================================
# DATE RANGE
# ============================================================

start, end = (
    st.session_state.fetch_dates
)


# ============================================================
# FETCH BUTTONS
# ============================================================

b1, b2 = st.columns(2)


# ============================================================
# FETCH INBOX + SPAM
# ============================================================

with b1:

    if st.button(
        '📥 Fetch Emails'
    ):

        st.session_state.batch_counter += 1

        batch = (
            st.session_state.batch_counter
        )

        use_uid = (
            not st.session_state.df.empty
            and st.session_state.last_uid is not None
        )

        with st.spinner(
            'Fetching Inbox + Spam...'
        ):

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=2
            ) as ex:

                f1 = ex.submit(
                    fetch_box,
                    user,
                    pwd,
                    'inbox',
                    start,
                    end,
                    use_uid,
                    st.session_state.last_uid,
                    batch
                )

                f2 = ex.submit(
                    fetch_box,
                    user,
                    pwd,
                    '[Gmail]/Spam',
                    start,
                    end,
                    False,
                    None,
                    batch
                )

                inbox, new_uid = (
                    f1.result()
                )

                spam, _ = (
                    f2.result()
                )

            st.session_state.df = merge_df(
                pd.concat(
                    [
                        inbox,
                        spam
                    ],
                    ignore_index=True
                ),
                st.session_state.df
            )

            st.session_state.last_uid = (
                new_uid
            )


# ============================================================
# FETCH SPAM ONLY
# ============================================================

with b2:

    if st.button(
        '🗑️ Fetch Spam Only'
    ):

        st.session_state.batch_counter += 1

        batch = (
            st.session_state.batch_counter
        )

        spam, _ = fetch_box(
            user,
            pwd,
            '[Gmail]/Spam',
            start,
            end,
            False,
            None,
            batch
        )

        st.session_state.spam_df = merge_df(
            spam,
            st.session_state.spam_df
        )


# ============================================================
# PROCESSED EMAILS
# ============================================================

st.subheader(
    '📬 Processed Emails'
)

if not st.session_state.df.empty:

    cols = [
        'Subject',
        'Date',
        'Domain',
        'SPF',
        'DKIM',
        'DMARC',
        'Type',
        'Blast/Sub ID',
        'Mailbox',
        'Batch_ID'
    ]

    display_df = (
        st.session_state.df[cols]
        .copy()
    )

    identifier_name = (
        get_identifier_column_name(
            display_df
        )
    )

    display_df = display_df.rename(
        columns={
            'Blast/Sub ID':
                identifier_name
        }
    )

    st.dataframe(
        display_df
        .style
        .apply(
            style_rows,
            axis=1
        ),
        use_container_width=True,
        column_config={
            'Batch_ID': None
        }
    )


# ============================================================
# FAILED AUTH EMAILS
# ============================================================

failed = st.session_state.df[
    (
        st.session_state.df['SPF'] != 'pass'
    )
    |
    (
        st.session_state.df['DKIM'] != 'pass'
    )
    |
    (
        st.session_state.df['DMARC'] != 'pass'
    )
].reset_index(
    drop=True
)


if not failed.empty:

    st.subheader(
        '❌ Failed Auth Emails'
    )

    failed_display = failed[
        [
            'Subject',
            'Domain',
            'SPF',
            'DKIM',
            'DMARC',
            'Type',
            'Blast/Sub ID',
            'Mailbox'
        ]
    ].copy()

    identifier_name = (
        get_identifier_column_name(
            failed_display
        )
    )

    failed_display = failed_display.rename(
        columns={
            'Blast/Sub ID':
                identifier_name
        }
    )

    st.dataframe(
        failed_display
        .style
        .apply(
            style_rows,
            axis=1
        ),
        use_container_width=True
    )

    st.info(
        f'Total Failed Rows: {len(failed)}'
    )


# ============================================================
# SPAM EMAILS
# ============================================================

if not st.session_state.spam_df.empty:

    st.subheader(
        '🚫 Spam Emails'
    )

    spam_display = st.session_state.spam_df[
        [
            'Subject',
            'Date',
            'Domain',
            'Type',
            'Blast/Sub ID',
            'Mailbox',
            'Batch_ID'
        ]
    ].copy()

    identifier_name = (
        get_identifier_column_name(
            spam_display
        )
    )

    spam_display = spam_display.rename(
        columns={
            'Blast/Sub ID':
                identifier_name
        }
    )

    st.dataframe(
        spam_display,
        use_container_width=True,
        column_config={
            'Batch_ID': None
        }
    )
