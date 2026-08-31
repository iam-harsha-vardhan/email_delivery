import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
import datetime
import re
import pandas as pd
import pytz
import base64
import concurrent.futures
from typing import List


# ============================================================
# BASIC PAGE
# ============================================================

st.set_page_config(
    page_title="Dynamic Multi-Account Inbox Comparator",
    layout="wide"
)

st.title(
    "📧 Dynamic Multi-Account Inbox Comparator"
)


# ============================================================
# CONFIG
# ============================================================

UID_SCAN_LIMIT = 2000
CHUNK_SIZE = 200


# ============================================================
# SESSION STATE
# ============================================================

if "creds_df" not in st.session_state:

    st.session_state.creds_df = pd.DataFrame(
        [
            {
                "Email": "",
                "Password": ""
            }
        ]
    )


if "mailbox_data" not in st.session_state:

    st.session_state.mailbox_data = {}


# ============================================================
# EMPTY MAILBOX STRUCTURE
# ============================================================

def get_empty_mailbox_structure():

    return {
        "last_uid": None,

        "df": pd.DataFrame(
            columns=[
                "UID",
                "Domain",
                "Subject",
                "From",
                "Message-ID",
                "Date",
                "Date_dt",
                "Blast/Sub ID",
                "Type",
                "SPF",
                "DKIM",
                "DMARC",
                "is_new"
            ]
        ),

        "uid_date_cache": {}
    }


# ============================================================
# MIME DECODER
# ============================================================

def decode_mime_words(s):

    if not s:
        return ""

    decoded = ""

    for word, enc in decode_header(s):

        if isinstance(word, bytes):

            try:

                decoded += word.decode(
                    enc or "utf-8",
                    errors="ignore"
                )

            except Exception:

                decoded += word.decode(
                    "utf-8",
                    errors="ignore"
                )

        else:

            decoded += word

    return decoded.strip()


# ============================================================
# DOMAIN
# ============================================================

def extract_domain_from_address(address):

    if not address:
        return "-"

    m = re.search(
        r'@([\w\.-]+)',
        address
    )

    return (
        m.group(1).lower()
        if m
        else "-"
    )


# ============================================================
# AUTHENTICATION RESULTS
# ============================================================

def extract_auth_results_from_headers(msg):

    auth = (
        msg.get(
            "Authentication-Results",
            ""
        )
        or
        " ".join(
            f"{h}: {v}"
            for h, v in msg.items()
        )
    )

    spf = "neutral"
    dkim = "neutral"
    dmarc = "neutral"

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


# ============================================================
# SUB-ID REGEX
#
# IMPORTANT:
# "_" is NOT part of the Sub ID.
#
# Example:
#
# GMFP-NL-SEXPT-997992-20260830-S-14539128-1_997992...
#
# becomes:
#
# GMFP-NL-SEXPT-997992-20260830-S-14539128-1
# ============================================================

ID_RE = re.compile(
    r'\b('
    r'GRM-[A-Za-z0-9.\-]+|'
    r'GMFP-[A-Za-z0-9.\-]+|'
    r'GTC-[A-Za-z0-9.\-]+|'
    r'GRTC-[A-Za-z0-9.\-]+'
    r')\b',
    re.I
)


# ============================================================
# SUB-ID TYPE
# ============================================================

def map_id_to_type(sub_id):

    if not sub_id:
        return "-"

    lid = sub_id.lower()

    if lid.startswith("grm"):
        return "FPR"

    if lid.startswith("gmfp"):
        return "FP"

    if lid.startswith("gtc"):
        return "FPTC"

    if lid.startswith("grtc"):
        return "FPRTC"

    return "-"


# ============================================================
# BASE64 DECODER
# ============================================================

def try_base64_variants(s):

    if not s or len(s) < 4:
        return None

    s = s.strip()

    if (
        s.startswith("<")
        and
        s.endswith(">")
    ):
        s = s[1:-1]

    variants = [
        s,
        s.replace("-", "+").replace("_", "/")
    ]

    for value in variants:

        value = re.sub(
            r"\s+",
            "",
            value
        )

        padding = "=" * (
            -len(value) % 4
        )

        candidate = (
            value +
            padding
        )

        for decoder in (
            base64.b64decode,
            base64.urlsafe_b64decode
        ):

            try:

                decoded = decoder(
                    candidate
                )

                text = decoded.decode(
                    "utf-8",
                    errors="ignore"
                )

                if text and text.strip():

                    return text

            except Exception:

                continue

    return None


# ============================================================
# FIND SUB-ID
# ============================================================

def find_subid_in_text(txt):

    if not txt:
        return None

    m = ID_RE.search(txt)

    return (
        m.group(1)
        if m
        else None
    )


# ============================================================
# EXTRACT SUB-ID FROM MESSAGE
# ============================================================

def extract_subid_from_msg(msg):

    msg_id_raw = decode_mime_words(
        msg.get(
            "Message-ID",
            ""
        )
        or
        msg.get(
            "Message-Id",
            ""
        )
        or
        ""
    )

    prefixes = (
        "GRM-",
        "GMFP-",
        "GTC-",
        "GRTC-"
    )

    if msg_id_raw:

        # ----------------------------------------------------
        # Remove domain part.
        # ----------------------------------------------------

        local_part = (
            msg_id_raw
            .strip("<>")
            .rsplit("@", 1)[0]
        )

        # ----------------------------------------------------
        # Split possible selectors.
        #
        # "_" is explicitly supported.
        # ----------------------------------------------------

        tokens = re.split(
            r'[_:|;,<>\s@]+',
            local_part
        )

        for token in tokens:

            token = token.strip()

            if not token:
                continue

            # ------------------------------------------------
            # Direct Sub ID
            # ------------------------------------------------

            if token.upper().startswith(
                prefixes
            ):

                return (
                    token,
                    map_id_to_type(token)
                )

            # ------------------------------------------------
            # Decode token
            # ------------------------------------------------

            decoded = try_base64_variants(
                token
            )

            if decoded:

                decoded = decoded.strip()

                if decoded.upper().startswith(
                    prefixes
                ):

                    return (
                        decoded,
                        map_id_to_type(decoded)
                    )

                m = find_subid_in_text(
                    decoded
                )

                if m:

                    return (
                        m,
                        map_id_to_type(m)
                    )

    # --------------------------------------------------------
    # Header fallback
    # --------------------------------------------------------

    headers_str = " ".join(
        f"{h}:{v}"
        for h, v in msg.items()
    )

    m = find_subid_in_text(
        headers_str
    )

    if m:

        return (
            m,
            map_id_to_type(m)
        )

    return None, "-"


# ============================================================
# BLAST-ID PATTERN
#
# Observed examples:
#
# 67159853o0qs
# 07951351kek7
# 30638613bap5
# 748499244e53
# 10685743xz87
#
# Exactly 12 alphanumeric characters,
# beginning with a digit.
# ============================================================

BLAST_ID_RE = re.compile(
    r'^[0-9][A-Za-z0-9]{11}$'
)


# ============================================================
# BLAST-ID VALIDATOR
# ============================================================

def is_valid_blast_id(value):

    if not value:
        return False

    value = value.strip()

    return bool(
        BLAST_ID_RE.fullmatch(
            value
        )
    )


# ============================================================
# MESSAGE-ID LOCAL PART
# ============================================================

def get_message_id_local_part(
    message_id
):

    if not message_id:
        return ""

    value = (
        message_id
        .strip()
        .strip("<>")
    )

    if "@" in value:

        value = value.rsplit(
            "@",
            1
        )[0]

    return value


# ============================================================
# SPLIT MESSAGE-ID INTO CANDIDATES
#
# Do not depend on "_" alone.
# ============================================================

def split_message_id_candidates(
    local_part
):

    if not local_part:
        return []

    candidates = [
        local_part
    ]

    # --------------------------------------------------------
    # Common selectors
    #
    # These are separators seen in generated identifiers.
    # --------------------------------------------------------

    pieces = re.split(
        r'[_:|;,<>\s]+',
        local_part
    )

    for piece in pieces:

        piece = piece.strip()

        if piece:

            candidates.append(
                piece
            )

    # --------------------------------------------------------
    # Remove duplicates while preserving order.
    # --------------------------------------------------------

    return list(
        dict.fromkeys(
            candidates
        )
    )


# ============================================================
# FIND BLAST IDS INSIDE DECODED TEXT
# ============================================================

def find_blast_ids_in_text(
    text
):

    if not text:
        return []

    found = []

    # --------------------------------------------------------
    # Exact decoded value
    # --------------------------------------------------------

    clean = text.strip()

    if is_valid_blast_id(
        clean
    ):

        found.append(
            clean.lower()
        )

    # --------------------------------------------------------
    # Search embedded Blast IDs
    # --------------------------------------------------------

    matches = re.findall(
        r'(?<![A-Za-z0-9])'
        r'[0-9][A-Za-z0-9]{11}'
        r'(?![A-Za-z0-9])',
        text
    )

    for value in matches:

        value = value.lower()

        if (
            is_valid_blast_id(value)
            and
            value not in found
        ):

            found.append(
                value
            )

    return found


# ============================================================
# EXTRACT BLAST IDs
#
# IMPORTANT:
# - Check original value
# - Check multiple selectors
# - Decode every candidate
# - Check decoded values
# - Support multiple Blast IDs
# - Remove duplicates
# ============================================================

def extract_blast_id(
    message_id
):

    if not message_id:
        return "-"

    found = []

    def add_value(value):

        if not value:
            return

        value = value.strip()

        # Direct Blast ID
        if is_valid_blast_id(
            value
        ):

            normalized = value.lower()

            if normalized not in found:

                found.append(
                    normalized
                )

        # Blast ID inside decoded text
        for blast in find_blast_ids_in_text(
            value
        ):

            if blast not in found:

                found.append(
                    blast
                )

    # --------------------------------------------------------
    # Get local part
    # --------------------------------------------------------

    local_part = get_message_id_local_part(
        message_id
    )

    if not local_part:

        return "-"

    # --------------------------------------------------------
    # Check complete local part
    # --------------------------------------------------------

    add_value(
        local_part
    )

    # --------------------------------------------------------
    # Split candidates
    # --------------------------------------------------------

    candidates = split_message_id_candidates(
        local_part
    )

    # --------------------------------------------------------
    # Decode every candidate
    # --------------------------------------------------------

    for candidate in candidates:

        add_value(
            candidate
        )

        decoded = try_base64_variants(
            candidate
        )

        if decoded:

            add_value(
                decoded
            )

            # ------------------------------------------------
            # Check nested candidates
            # ------------------------------------------------

            nested = re.split(
                r'[_:|;,\s]+',
                decoded
            )

            for value in nested:

                value = value.strip()

                if not value:
                    continue

                add_value(
                    value
                )

                nested_decoded = (
                    try_base64_variants(
                        value
                    )
                )

                if nested_decoded:

                    add_value(
                        nested_decoded
                    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    if found:

        return ", ".join(
            found
        )

    return "-"


# ============================================================
# DATE FORMAT
# ============================================================

def format_date_to_ist_string(
    raw_date
):

    if not raw_date:

        return "-", None

    try:

        dt = parsedate_to_datetime(
            raw_date
        )

    except Exception:

        return raw_date, None

    if dt.tzinfo is None:

        dt = dt.replace(
            tzinfo=datetime.timezone.utc
        )

    ist = pytz.timezone(
        "Asia/Kolkata"
    )

    dt_ist = dt.astimezone(
        ist
    )

    dt_ist_naive = (
        dt_ist.replace(
            tzinfo=None
        )
    )

    formatted = dt_ist.strftime(
        "%d-%b-%Y %I:%M %p"
    )

    return (
        formatted,
        dt_ist_naive
    )


# ============================================================
# FETCH RESPONSE PARSER
# ============================================================

def parse_fetch_parts_for_uid_and_date(
    fetch_response_parts
) -> List[tuple]:

    results = []

    for part in fetch_response_parts:

        if not isinstance(
            part,
            tuple
        ):
            continue

        header_bytes, body_bytes = (
            part[0],
            part[1]
        )

        try:

            meta = header_bytes.decode(
                "utf-8",
                errors="ignore"
            )

        except Exception:

            try:

                meta = str(
                    header_bytes
                )

            except Exception:

                meta = ""

        uid_match = re.search(
            r'UID\s+(\d+)',
            meta
        )

        uid_str = (
            uid_match.group(1)
            if uid_match
            else None
        )

        raw_date = ""

        if body_bytes:

            try:

                body_text = body_bytes.decode(
                    "utf-8",
                    errors="ignore"
                )

            except Exception:

                body_text = str(
                    body_bytes
                )

            m = re.search(
                r'Date:\s*(.+)',
                body_text,
                flags=re.I
            )

            if m:

                raw_date = m.group(1).strip()

        if uid_str:

            results.append(
                (
                    uid_str,
                    raw_date
                )
            )

    return results


# ============================================================
# CORE FETCH
# ============================================================

def fetch_inbox_emails_single(
    email_addr,
    password,
    last_uid=None,
    fetch_type="incremental",
    fetch_n=None,
    fetch_unit="emails",
    uid_scan_limit=UID_SCAN_LIMIT,
    chunk_size=CHUNK_SIZE
):

    results = []

    new_last_uid = last_uid

    try:

        email_addr = email_addr.strip()
        password = password.strip()

        imap = imaplib.IMAP4_SSL(
            "imap.gmail.com"
        )

        imap.login(
            email_addr,
            password
        )

        imap.select(
            "inbox"
        )

        uids = []

        # ====================================================
        # INCREMENTAL
        # ====================================================

        if (
            fetch_type == "incremental"
            and
            last_uid is not None
        ):

            next_uid = (
                int(last_uid) + 1
            )

            status, data = imap.uid(
                "search",
                None,
                f"UID {next_uid}:*"
            )

            if (
                status == "OK"
                and
                data
                and
                data[0]
            ):

                raw_uids = data[0].split()

                uids = [
                    u
                    for u in raw_uids
                    if int(
                        u.decode()
                    ) >= next_uid
                ]

        # ====================================================
        # LAST N EMAILS
        # ====================================================

        elif (
            fetch_unit == "emails"
            and
            fetch_n
        ):

            status, data = imap.uid(
                "search",
                None,
                "ALL"
            )

            if (
                status == "OK"
                and
                data
                and
                data[0]
            ):

                all_uids = data[0].split()

                uids = (
                    all_uids[
                        -int(fetch_n):
                    ]
                )

        # ====================================================
        # LAST N HOURS / MINUTES
        # ====================================================

        elif (
            fetch_unit in (
                "hours",
                "minutes"
            )
            and
            fetch_n
        ):

            ist = pytz.timezone(
                "Asia/Kolkata"
            )

            now_ist = (
                datetime.datetime
                .now(ist)
                .replace(
                    tzinfo=None
                )
            )

            if fetch_unit == "hours":

                cutoff = (
                    now_ist
                    -
                    datetime.timedelta(
                        hours=int(fetch_n)
                    )
                )

            else:

                cutoff = (
                    now_ist
                    -
                    datetime.timedelta(
                        minutes=int(fetch_n)
                    )
                )

            status, data = imap.uid(
                "search",
                None,
                "ALL"
            )

            if (
                status == "OK"
                and
                data
                and
                data[0]
            ):

                all_uids = data[0].split()

                uids_to_check = (
                    all_uids[
                        -uid_scan_limit:
                    ]
                    if
                    len(all_uids)
                    >
                    uid_scan_limit
                    else
                    all_uids
                )

                matched_uids = []

                for i in range(
                    0,
                    len(uids_to_check),
                    chunk_size
                ):

                    chunk = (
                        uids_to_check[
                            i:i + chunk_size
                        ]
                    )

                    uid_seq = b",".join(
                        chunk
                    )

                    try:

                        res, fdata = imap.uid(
                            "fetch",
                            uid_seq,
                            "(BODY.PEEK[HEADER.FIELDS (DATE)])"
                        )

                    except Exception:

                        for u in chunk:

                            try:

                                uid_str = (
                                    u.decode()
                                )

                                r, md = imap.uid(
                                    "fetch",
                                    uid_str,
                                    "(BODY.PEEK[HEADER.FIELDS (DATE)])"
                                )

                                if (
                                    r != "OK"
                                    or
                                    not md
                                ):
                                    continue

                                parsed = (
                                    parse_fetch_parts_for_uid_and_date(
                                        md
                                    )
                                )

                                for (
                                    uid_s,
                                    raw_date
                                ) in parsed:

                                    if not raw_date:

                                        continue

                                    _, dt = (
                                        format_date_to_ist_string(
                                            raw_date
                                        )
                                    )

                                    if (
                                        dt
                                        and
                                        dt >= cutoff
                                    ):

                                        matched_uids.append(
                                            uid_s.encode()
                                        )

                            except Exception:

                                continue

                        continue

                    parsed = (
                        parse_fetch_parts_for_uid_and_date(
                            fdata
                        )
                    )

                    for (
                        uid_str,
                        raw_date
                    ) in parsed:

                        if not raw_date:

                            continue

                        _, dt = (
                            format_date_to_ist_string(
                                raw_date
                            )
                        )

                        if (
                            dt
                            and
                            dt >= cutoff
                        ):

                            matched_uids.append(
                                uid_str.encode()
                            )

                uids = matched_uids

        # ====================================================
        # DEFAULT TODAY
        # ====================================================

        else:

            ist = pytz.timezone(
                "Asia/Kolkata"
            )

            today_ist = (
                datetime.datetime
                .now(ist)
                .strftime(
                    "%d-%b-%Y"
                )
            )

            status, data = imap.uid(
                "search",
                None,
                f'(SINCE "{today_ist}")'
            )

            if (
                status == "OK"
                and
                data
                and
                data[0]
            ):

                uids = data[0].split()

        # ====================================================
        # NO EMAILS
        # ====================================================

        if not uids:

            imap.logout()

            return (
                pd.DataFrame(results),
                new_last_uid
            )

        # ====================================================
        # BATCH FETCH
        # ====================================================

        fetch_uid_bytes = uids

        for i in range(
            0,
            len(fetch_uid_bytes),
            chunk_size
        ):

            chunk = (
                fetch_uid_bytes[
                    i:i + chunk_size
                ]
            )

            uid_seq = b",".join(
                chunk
            )

            try:

                res, fdata = imap.uid(
                    "fetch",
                    uid_seq,
                    "(BODY.PEEK[HEADER])"
                )

            except Exception:

                # ============================================
                # FALLBACK SINGLE FETCH
                # ============================================

                for u in chunk:

                    try:

                        uid_s = u.decode()

                        r2, md2 = imap.uid(
                            "fetch",
                            uid_s,
                            "(BODY.PEEK[HEADER])"
                        )

                        if (
                            r2 != "OK"
                            or
                            not md2
                            or
                            not isinstance(
                                md2[0],
                                tuple
                            )
                        ):
                            continue

                        msg = email.message_from_bytes(
                            md2[0][1]
                        )

                        subject = (
                            decode_mime_words(
                                msg.get(
                                    "Subject",
                                    "No Subject"
                                )
                            )
                        )

                        from_h = (
                            decode_mime_words(
                                msg.get(
                                    "From",
                                    "-"
                                )
                            )
                        )

                        domain = (
                            extract_domain_from_address(
                                from_h
                            )
                        )

                        spf, dkim, dmarc = (
                            extract_auth_results_from_headers(
                                msg
                            )
                        )

                        sub_id, id_type = (
                            extract_subid_from_msg(
                                msg
                            )
                        )

                        message_id = (
                            decode_mime_words(
                                msg.get(
                                    "Message-ID",
                                    ""
                                )
                            )
                        )

                        blast_id = (
                            extract_blast_id(
                                message_id
                            )
                        )

                        # ------------------------------------
                        # Unified Identifier
                        # ------------------------------------

                        identifier = (
                            sub_id
                            if sub_id
                            else (
                                blast_id
                                if blast_id != "-"
                                else "-"
                            )
                        )

                        raw_date = (
                            msg.get(
                                "Date",
                                ""
                            )
                        )

                        formatted, dt = (
                            format_date_to_ist_string(
                                raw_date
                            )
                        )

                        results.append(
                            {
                                "UID": uid_s,
                                "Domain": domain,
                                "Subject": subject,
                                "From": from_h,
                                "Message-ID": message_id,
                                "Date": formatted,
                                "Date_dt": dt,
                                "Blast/Sub ID": identifier,
                                "Type": id_type,
                                "SPF": spf,
                                "DKIM": dkim,
                                "DMARC": dmarc
                            }
                        )

                        if (
                            new_last_uid is None
                            or
                            (
                                uid_s.isdigit()
                                and
                                int(uid_s)
                                >
                                int(new_last_uid)
                            )
                        ):

                            new_last_uid = uid_s

                    except Exception:

                        continue

                continue

            # =================================================
            # BATCH RESPONSE
            # =================================================

            for part in fdata:

                if not isinstance(
                    part,
                    tuple
                ):
                    continue

                hdr_bytes = part[1]

                try:

                    msg = email.message_from_bytes(
                        hdr_bytes
                    )

                except Exception:

                    continue

                uid_found = None

                try:

                    meta = part[0].decode(
                        "utf-8",
                        errors="ignore"
                    )

                    m = re.search(
                        r'UID\s+(\d+)',
                        meta
                    )

                    if m:

                        uid_found = (
                            m.group(1)
                        )

                except Exception:

                    uid_found = None

                subject = (
                    decode_mime_words(
                        msg.get(
                            "Subject",
                            "No Subject"
                        )
                    )
                )

                from_h = (
                    decode_mime_words(
                        msg.get(
                            "From",
                            "-"
                        )
                    )
                )

                domain = (
                    extract_domain_from_address(
                        from_h
                    )
                )

                spf, dkim, dmarc = (
                    extract_auth_results_from_headers(
                        msg
                    )
                )

                # ------------------------------------------------
                # Existing Sub ID extraction
                # ------------------------------------------------

                sub_id, id_type = (
                    extract_subid_from_msg(
                        msg
                    )
                )

                # ------------------------------------------------
                # Message ID
                # ------------------------------------------------

                message_id = (
                    decode_mime_words(
                        msg.get(
                            "Message-ID",
                            ""
                        )
                    )
                )

                # ------------------------------------------------
                # Blast ID
                # ------------------------------------------------

                blast_id = (
                    extract_blast_id(
                        message_id
                    )
                )

                # ------------------------------------------------
                # Unified identifier
                #
                # Sub ID priority.
                # Blast ID fallback.
                # ------------------------------------------------

                identifier = (
                    sub_id
                    if sub_id
                    else (
                        blast_id
                        if blast_id != "-"
                        else "-"
                    )
                )

                raw_date = (
                    msg.get(
                        "Date",
                        ""
                    )
                )

                formatted, dt = (
                    format_date_to_ist_string(
                        raw_date
                    )
                )

                uid_str = (
                    uid_found
                    if uid_found
                    else None
                )

                if uid_str is None:

                    continue

                results.append(
                    {
                        "UID": uid_str,
                        "Domain": domain,
                        "Subject": subject,
                        "From": from_h,
                        "Message-ID": message_id,
                        "Date": formatted,
                        "Date_dt": dt,
                        "Blast/Sub ID": identifier,
                        "Type": id_type,
                        "SPF": spf,
                        "DKIM": dkim,
                        "DMARC": dmarc
                    }
                )

                if (
                    new_last_uid is None
                    or
                    (
                        uid_str.isdigit()
                        and
                        int(uid_str)
                        >
                        int(new_last_uid)
                    )
                ):

                    new_last_uid = uid_str

        imap.logout()

    except Exception as e:

        raise Exception(
            f"IMAP Error: {e}"
        )

    df = pd.DataFrame(
        results
    )

    return (
        df,
        new_last_uid
    )


# ============================================================
# STYLING
# ============================================================

def highlight_new_rows(row):

    return (
        [
            "background-color: #90EE90"
        ] * len(row)
        if
        row.get(
            "is_new",
            False
        )
        else
        [
            ""
        ] * len(row)
    )


def highlight_presence_row(row):

    try:

        if (
            str(
                row.get(
                    "Auth",
                    ""
                )
            ).lower()
            !=
            "pass"
        ):

            style = (
                "background-color: "
                "rgba(255, 0, 0, 0.15)"
            )

            return [
                style
            ] * len(row)

    except Exception:

        pass

    return highlight_new_rows(
        row
    )


# ============================================================
# DYNAMIC IDENTIFIER COLUMN NAME
# ============================================================

def get_identifier_column_name(
    df
):

    if df.empty:

        return "Blast/Sub ID"

    values = (
        df["Blast/Sub ID"]
        .dropna()
        .astype(str)
        .str.strip()
    )

    values = values[
        values != "-"
    ]

    if values.empty:

        return "Blast/Sub ID"

    subid_mask = (
        values.str.match(
            r'^(GRM|GMFP|GTC|GRTC)-',
            case=False,
            na=False
        )
    )

    subid_count = int(
        subid_mask.sum()
    )

    blast_count = int(
        (~subid_mask).sum()
    )

    if (
        subid_count > 0
        and
        blast_count == 0
    ):

        return "Sub ID"

    if (
        blast_count > 0
        and
        subid_count == 0
    ):

        return "Blast ID"

    return "Blast/Sub ID"


# ============================================================
# THREAD SAFE FETCH WORKER
# ============================================================

def fetch_worker(
    email_addr,
    pwd,
    last_uid,
    fetch_type,
    fetch_n,
    fetch_unit
):

    try:

        df, n_uid = (
            fetch_inbox_emails_single(
                email_addr,
                pwd,
                last_uid=last_uid,
                fetch_type=fetch_type,
                fetch_n=fetch_n,
                fetch_unit=fetch_unit,
                uid_scan_limit=UID_SCAN_LIMIT,
                chunk_size=CHUNK_SIZE
            )
        )

        return (
            email_addr,
            df,
            n_uid,
            None
        )

    except Exception as e:

        return (
            email_addr,
            pd.DataFrame(),
            last_uid,
            str(e)
        )


# ============================================================
# PROCESS FETCH
# ============================================================

def process_fetch(
    fetch_type,
    fetch_n=None,
    fetch_unit="emails"
):

    any_run = False

    # --------------------------------------------------------
    # Reset old new-state
    # --------------------------------------------------------

    for email_addr, mailbox in (
        st.session_state.mailbox_data.items()
    ):

        if (
            "is_new"
            in
            mailbox["df"].columns
        ):

            mailbox["df"]["is_new"] = False

    futures = []

    errors = []

    # --------------------------------------------------------
    # Parallel account fetch
    # --------------------------------------------------------

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=10
    ) as executor:

        for i, r in (
            st.session_state.creds_df.iterrows()
        ):

            email_addr = (
                r.get(
                    "Email",
                    ""
                )
                .strip()
            )

            pwd = (
                r.get(
                    "Password",
                    ""
                )
                .strip()
            )

            if (
                not email_addr
                or
                not pwd
            ):

                continue

            if (
                email_addr
                not in
                st.session_state.mailbox_data
            ):

                st.session_state.mailbox_data[
                    email_addr
                ] = (
                    get_empty_mailbox_structure()
                )

            mailbox = (
                st.session_state.mailbox_data[
                    email_addr
                ]
            )

            futures.append(
                executor.submit(
                    fetch_worker,
                    email_addr,
                    pwd,
                    mailbox.get(
                        "last_uid"
                    ),
                    fetch_type,
                    fetch_n,
                    fetch_unit
                )
            )

    # --------------------------------------------------------
    # Merge results
    # --------------------------------------------------------

    for future in (
        concurrent.futures.as_completed(
            futures
        )
    ):

        email_addr, df_new, new_uid, err = (
            future.result()
        )

        if err:

            errors.append(
                f"{email_addr}: {err}"
            )

        elif (
            df_new is not None
            and
            not df_new.empty
        ):

            any_run = True

            df_new["is_new"] = True

            mailbox = (
                st.session_state.mailbox_data[
                    email_addr
                ]
            )

            mailbox["df"] = (
                pd.concat(
                    [
                        mailbox["df"],
                        df_new
                    ],
                    ignore_index=True
                )
                .drop_duplicates(
                    subset=["UID"],
                    keep="last"
                )
            )

            mailbox["last_uid"] = (
                new_uid
            )

    # --------------------------------------------------------
    # Errors
    # --------------------------------------------------------

    if errors:

        for error in errors:

            st.error(
                error
            )

    return any_run


# ============================================================
# ACCOUNT CREDENTIALS
# ============================================================

st.markdown(
    "### 📋 Account Credentials"
)

st.info(
    "Add accounts (App Password recommended for Gmail)."
)

column_config = {

    "Email":
        st.column_config.TextColumn(
            "Email",
            width="medium",
            required=True
        ),

    "Password":
        st.column_config.TextColumn(
            "App Password",
            width="medium",
            required=True
        )

}

edited_df = st.data_editor(
    st.session_state.creds_df,
    num_rows="dynamic",
    column_config=column_config,
    key="editor",
    use_container_width=True,
    hide_index=True
)

st.session_state.creds_df = (
    edited_df
)


# ============================================================
# CONTROL BAR
# ============================================================

st.markdown("---")

col_f1, col_f2, col_f3, col_f4 = (
    st.columns(
        [
            1.2,
            1.2,
            2.5,
            1.2
        ]
    )
)


# ------------------------------------------------------------
# INCREMENTAL
# ------------------------------------------------------------

with col_f1:

    if st.button(
        "🔄 Fetch New (incremental)"
    ):

        ok = process_fetch(
            "incremental"
        )

        st.success(
            "Fetched incremental emails."
            if ok
            else
            "No new emails found."
        )


# ------------------------------------------------------------
# LAST N
# ------------------------------------------------------------

with col_f2:

    fetch_n = st.number_input(
        "N",
        min_value=1,
        value=100,
        step=1,
        label_visibility="collapsed",
        key="compact_fetch_n2"
    )

    fetch_unit = st.selectbox(
        "Unit",
        [
            "emails",
            "hours",
            "minutes"
        ],
        index=2,
        label_visibility="collapsed",
        key="compact_unit2"
    )

    if st.button(
        "📥 Fetch Last N"
    ):

        ok = process_fetch(
            "last_n",
            fetch_n=fetch_n,
            fetch_unit=fetch_unit
        )

        st.success(
            f"Fetched last {fetch_n} {fetch_unit}."
            if ok
            else
            "No new emails found."
        )


# ------------------------------------------------------------
# REQUIRED ACCOUNT COUNT
# ------------------------------------------------------------

with col_f3:

    non_empty = [
        r
        for _, r
        in st.session_state.creds_df.iterrows()
        if r.get(
            "Email",
            ""
        ).strip()
    ]

    avail = max(
        1,
        len(non_empty)
    )

    default_n = (
        4
        if avail >= 4
        else avail
    )

    required_accounts_count = (
        st.number_input(
            "Require Blast/Sub ID presence in at least N accounts",
            min_value=1,
            max_value=avail,
            value=default_n,
            step=1,
            key="req_n"
        )
    )


# ------------------------------------------------------------
# CLEAR ALL
# ------------------------------------------------------------

with col_f4:

    if st.button(
        "🗑️ Clear All"
    ):

        st.session_state.mailbox_data = {}

        st.success(
            "Cleared all fetched emails."
        )

        st.rerun()


# ============================================================
# EMAIL COUNTS
# ============================================================

st.markdown("---")

st.markdown(
    "### 📊 Email Counts per Account"
)

if not st.session_state.mailbox_data:

    st.write(
        "No data fetched yet."
    )

else:

    active_emails = list(
        st.session_state.mailbox_data.keys()
    )

    if active_emails:

        cols = st.columns(
            len(active_emails)
        )

        for i, em in enumerate(
            active_emails
        ):

            mailbox = (
                st.session_state.mailbox_data[
                    em
                ]
            )

            total = len(
                mailbox["df"]
            )

            newc = int(
                mailbox["df"][
                    "is_new"
                ].sum()
            )
            if (
                "is_new"
                in
                mailbox["df"].columns
            )
            else 0

            with cols[i]:

                st.metric(
                    label=em.split("@")[0],
                    value=total,
                    delta=(
                        f"{newc} New"
                        if newc > 0
                        else None
                    )
                )


# ============================================================
# BUILD PRESENCE + ASSET MAPS
# ============================================================

st.markdown("---")

all_keys = set()

email_presence_map = {}

new_email_keys = set()

valid_emails = [
    r["Email"]
    for _, r
    in st.session_state.creds_df.iterrows()
    if r["Email"]
    in
    st.session_state.mailbox_data
]

asset_map = {}


for email_addr in valid_emails:

    df_acc = (
        st.session_state.mailbox_data[
            email_addr
        ]["df"]
    )

    keys = set()

    for _, row in df_acc.iterrows():

        # ----------------------------------------------------
        # Unified identifier
        # ----------------------------------------------------

        identifier = (
            row.get(
                "Blast/Sub ID",
                "-"
            )
            or
            "-"
        )

        key = (
            row["Domain"],
            row["Subject"],
            row["From"],
            row["SPF"],
            row["DKIM"],
            row["DMARC"],
            identifier
        )

        keys.add(
            key
        )

        if row.get(
            "is_new",
            False
        ):

            new_email_keys.add(
                key
            )

        # ----------------------------------------------------
        # Asset grouping
        # ----------------------------------------------------

        asset_key = (
            row.get(
                "Domain",
                "-"
            ),
            row.get(
                "From",
                "-"
            ),
            row.get(
                "Subject",
                "-"
            )
        )

        asset = asset_map.setdefault(
            asset_key,
            {
                "accounts": set(),
                "identifiers": set(),
                "rows": []
            }
        )

        asset["accounts"].add(
            email_addr
        )

        if (
            identifier
            and
            identifier != "-"
        ):

            # A mixed value such as:
            #
            # 30638613bap5, 67159853o0qs
            #
            # is kept as one identifier value in the
            # per-message record.
            asset["identifiers"].add(
                identifier
            )

        asset["rows"].append(
            {
                "account": email_addr,
                "UID": row.get("UID"),
                "Message-ID": row.get(
                    "Message-ID"
                ),
                "Date": row.get("Date"),
                "Date_dt": row.get(
                    "Date_dt"
                ),
                "Blast/Sub ID": identifier,
                "SPF": row.get("SPF"),
                "DKIM": row.get("DKIM"),
                "DMARC": row.get("DMARC"),
                "is_new": bool(
                    row.get(
                        "is_new",
                        False
                    )
                )
            }
        )

    email_presence_map[
        email_addr
    ] = keys

    all_keys.update(
        keys
    )


# ============================================================
# IDENTIFIER COLUMN TYPE
# ============================================================

all_identifier_frames = []

for email_addr in valid_emails:

    df_tmp = (
        st.session_state.mailbox_data[
            email_addr
        ]["df"]
    )

    if not df_tmp.empty:

        all_identifier_frames.append(
            df_tmp[
                ["Blast/Sub ID"]
            ]
        )

if all_identifier_frames:

    combined_identifier_df = (
        pd.concat(
            all_identifier_frames,
            ignore_index=True
        )
    )

else:

    combined_identifier_df = pd.DataFrame(
        columns=[
            "Blast/Sub ID"
        ]
    )

identifier_column_name = (
    get_identifier_column_name(
        combined_identifier_df
    )
)


# ============================================================
# TOP: DYNAMIC IDENTIFIER CONSENSUS
# ============================================================

st.subheader(
    f"🔎 {identifier_column_name} Consensus "
    f"(≥ {required_accounts_count} accounts)"
)

identifier_rows = []


for (
    domain,
    from_val,
    subject
), info in asset_map.items():

    if (
        len(info["accounts"])
        <
        required_accounts_count
    ):

        continue

    # --------------------------------------------------------
    # All identifiers associated with this asset
    # --------------------------------------------------------

    for identifier in sorted(
        list(
            info["identifiers"]
        )
    ):

        identifier_rows_for_asset = [
            r
            for r
            in info["rows"]
            if (
                r.get(
                    "Blast/Sub ID",
                    "-"
                )
                or
                "-"
            )
            ==
            identifier
        ]

        identifier_accounts = {
            r["account"]
            for r
            in identifier_rows_for_asset
        }

        if (
            len(identifier_accounts)
            <
            required_accounts_count
        ):

            continue

        # ----------------------------------------------------
        # Require all auths to pass
        # ----------------------------------------------------

        all_auth_pass = True

        for r in identifier_rows_for_asset:

            if not (
                str(
                    r.get(
                        "SPF",
                        ""
                    )
                ).lower()
                ==
                "pass"

                and

                str(
                    r.get(
                        "DKIM",
                        ""
                    )
                ).lower()
                ==
                "pass"

                and

                str(
                    r.get(
                        "DMARC",
                        ""
                    )
                ).lower()
                ==
                "pass"
            ):

                all_auth_pass = False

                break

        if not all_auth_pass:

            continue

        # ----------------------------------------------------
        # Latest time
        # ----------------------------------------------------

        latest_dt = None

        latest_str = "-"

        any_new = False

        for r in identifier_rows_for_asset:

            dt = r.get(
                "Date_dt"
            )

            if (
                dt is not None
                and
                (
                    latest_dt is None
                    or
                    dt > latest_dt
                )
            ):

                latest_dt = dt

                latest_str = (
                    r.get(
                        "Date"
                    )
                    or
                    latest_str
                )

            if r.get(
                "is_new",
                False
            ):

                any_new = True

        row = {

            "Domain":
                domain,

            "From":
                from_val,

            "Subject":
                subject,

            identifier_column_name:
                identifier,

            "Time (IST)":
                latest_str,

            "is_new":
                any_new
        }

        for em in valid_emails:

            row[
                em.split("@")[0]
            ] = (
                "✅"
                if
                em
                in
                identifier_accounts
                else
                "❌"
            )

        identifier_rows.append(
            (
                latest_dt,
                row
            )
        )


identifier_rows_sorted = [
    r
    for _, r
    in sorted(
        identifier_rows,
        key=lambda x: (
            x[0] is None,
            x[0]
        ),
        reverse=True
    )
]


if identifier_rows_sorted:

    identifier_df = pd.DataFrame(
        [
            row
            for _, row
            in identifier_rows_sorted
        ]
    )

    per_acc_cols = [
        e.split("@")[0]
        for e in valid_emails
    ]

    display_cols = [
        "Domain",
        "From",
        "Subject",
        identifier_column_name,
        "Time (IST)"
    ] + per_acc_cols + [
        "is_new"
    ]

    identifier_df = (
        identifier_df.reindex(
            columns=display_cols,
            fill_value="-"
        )
    )

    st.dataframe(
        identifier_df
        .style
        .apply(
            highlight_new_rows,
            axis=1
        ),
        hide_index=True,
        column_config={
            "is_new": None
        },
        use_container_width=True
    )

else:

    st.info(
        f"No {identifier_column_name} values "
        f"that meet the threshold of "
        f"{required_accounts_count} accounts "
        f"with all auths passing."
    )


# ============================================================
# MIDDLE: PRESENCE TABLE
# ============================================================

qualifying_identifiers = {}


for (
    domain,
    from_val,
    subject
), info in asset_map.items():

    if (
        len(info["accounts"])
        <
        required_accounts_count
    ):

        continue

    for identifier in (
        info["identifiers"]
    ):

        identifier_rows_for_asset = [
            r
            for r
            in info["rows"]
            if (
                r.get(
                    "Blast/Sub ID",
                    "-"
                )
                or
                "-"
            )
            ==
            identifier
        ]

        identifier_accounts = {
            r["account"]
            for r in identifier_rows_for_asset
        }

        if (
            len(identifier_accounts)
            >=
            required_accounts_count
        ):

            qualifying_identifiers.setdefault(
                (
                    domain,
                    from_val,
                    subject
                ),
                []
            ).append(
                identifier
            )


rows = []


if all_keys:

    sorted_keys = sorted(
        list(
            all_keys
        ),
        key=lambda k: (
            k not in new_email_keys,
            k[0],
            k[1]
        )
    )

    for (
        domain,
        subject,
        from_val,
        spf,
        dkim,
        dmarc,
        identifier
    ) in sorted_keys:

        latest_dt = None

        latest_str = "-"

        auth_pass_for_row = True

        for em in valid_emails:

            df_acc = (
                st.session_state.mailbox_data[
                    em
                ]["df"]
            )

            matches = df_acc[
                (
                    df_acc["Domain"]
                    ==
                    domain
                )
                &
                (
                    df_acc["Subject"]
                    ==
                    subject
                )
                &
                (
                    df_acc["From"]
                    ==
                    from_val
                )
                &
                (
                    df_acc[
                        "Blast/Sub ID"
                    ]
                    ==
                    identifier
                )
            ]

            for _, m in (
                matches.iterrows()
            ):

                dt = m.get(
                    "Date_dt"
                )

                if (
                    dt is not None
                    and
                    (
                        latest_dt is None
                        or
                        dt > latest_dt
                    )
                ):

                    latest_dt = dt

                    latest_str = (
                        m.get(
                            "Date"
                        )
                        or
                        latest_str
                    )

                if not (
                    str(
                        m.get(
                            "SPF",
                            ""
                        )
                    ).lower()
                    ==
                    "pass"

                    and

                    str(
                        m.get(
                            "DKIM",
                            ""
                        )
                    ).lower()
                    ==
                    "pass"

                    and

                    str(
                        m.get(
                            "DMARC",
                            ""
                        )
                    ).lower()
                    ==
                    "pass"
                ):

                    auth_pass_for_row = False

        qual_key = (
            domain,
            from_val,
            subject
        )

        qual_list = (
            qualifying_identifiers.get(
                qual_key,
                []
            )
        )

        identifiers_cell = (
            ", ".join(
                qual_list
            )
            if qual_list
            else
            "-"
        )

        row = {

            "Domain":
                domain,

            "From":
                from_val,

            "Subject":
                subject,

            f"{identifier_column_name} (raw)":
                identifier,

            "Time (IST)":
                latest_str,

            "Auth":
                (
                    "Pass"
                    if auth_pass_for_row
                    else
                    "Fail"
                ),

            f"{identifier_column_name}s (qualifying)":
                identifiers_cell,

            "is_new":
                (
                    domain,
                    subject,
                    from_val,
                    spf,
                    dkim,
                    dmarc,
                    identifier
                )
                in
                new_email_keys,

            "Date_dt_sort":
                latest_dt
        }

        for em in valid_emails:

            row[
                em.split("@")[0]
            ] = (
                "✅"
                if
                (
                    domain,
                    subject,
                    from_val,
                    spf,
                    dkim,
                    dmarc,
                    identifier
                )
                in
                email_presence_map[
                    em
                ]
                else
                "❌"
            )

        rows.append(
            row
        )


if rows:

    presence_df = pd.DataFrame(
        rows
    )

    if (
        "Date_dt_sort"
        in
        presence_df.columns
    ):

        presence_df = (
            presence_df.sort_values(
                by=[
                    "Date_dt_sort"
                ],
                ascending=False,
                na_position="last",
                ignore_index=True
            )
        )

    st.subheader(
        "📋 Email Presence Table "
        "(Newest on Top)"
    )

    if not presence_df.empty:

        per_account_cols = [
            e.split("@")[0]
            for e in valid_emails
        ]

        display_cols = [
            "Domain",
            "From",
            "Subject",
            f"{identifier_column_name} (raw)",
            "Time (IST)"
        ] + per_account_cols + [
            f"{identifier_column_name}s (qualifying)",
            "Auth",
            "is_new"
        ]

        presence_df = (
            presence_df.reindex(
                columns=display_cols,
                fill_value="-"
            )
        )

        st.dataframe(
            presence_df
            .style
            .apply(
                highlight_presence_row,
                axis=1
            ),
            hide_index=True,
            column_config={
                "is_new": None
            },
            use_container_width=True
        )

    else:

        st.info(
            "No presence rows to show."
        )

else:

    st.info(
        "No emails found in the active accounts."
    )


# ============================================================
# RAW PER-ACCOUNT MESSAGES
# ============================================================

st.markdown("---")

with st.expander(
    "Show Individual Raw Messages"
):

    for em in valid_emails:

        mailbox = (
            st.session_state.mailbox_data[
                em
            ]
        )

        st.markdown(
            f"**{em}** — "
            f"Stored: {len(mailbox['df'])}"
        )

        if not mailbox["df"].empty:

            df_to_show = (
                mailbox["df"].copy()
            )

            df_to_show["UID_int"] = (
                pd.to_numeric(
                    df_to_show["UID"],
                    errors="coerce"
                )
            )

            sorted_show = (
                df_to_show.sort_values(
                    by=[
                        "is_new",
                        "Date_dt",
                        "UID_int"
                    ],
                    ascending=[
                        False,
                        False,
                        False
                    ]
                )
            )

            st.dataframe(
                sorted_show.drop(
                    columns=[
                        "UID_int"
                    ]
                )
                .style
                .apply(
                    highlight_new_rows,
                    axis=1
                ),
                hide_index=True,
                use_container_width=True
            )
