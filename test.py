# email_auth_checker_app.py
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

# ---------------- DATAFRAME COLUMNS ----------------
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
            key="date_box",
            help="Select start & end dates for fetch"
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
        if st.button("🔁", help="Clear all data and credentials"):
            # keep date_box and fetch_dates
            keys = list(st.session_state.keys())
            for k in keys:
                if k not in ['date_box', 'fetch_dates']:
                    del st.session_state[k]
            st.experimental_rerun()

if not email_input or not password_input:
    st.warning("Please enter both Gmail address and an App Password.")
    st.stop()

START_DATE, END_DATE = st.session_state.fetch_dates
IS_SINGLE_DAY = START_DATE == END_DATE

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
        except Exception:
            out += str(part)
    return out.strip()

def format_date_ist(date_str):
    if not date_str:
        return "-"
    try:
        dt = parsedate_to_datetime(date_str)
        ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
        return dt.astimezone(ist).strftime("%d-%b-%Y %I:%M %p")
    except Exception:
        return str(date_str)

# Sub ID extraction logic (keeps your original ID patterns)
def extract_id_details(search_string, data):
    sub_id_match = re.search(
        r'(GTC-[^@_\s]+|GMFP-[^@_\s]+|GRM-[^@_\s]+|GRTC-[^@_\s]+)', 
        search_string, re.I
    )
    if sub_id_match:
        sid = sub_id_match.group(1)
        data["Sub ID"] = sid
        l = sid.lower()
        if 'grm' in l:
            data["Type"] = "FPR"
        elif 'gmfp' in l:
            data["Type"] = "FP"
        elif 'gtc' in l:
            data["Type"] = "FPTC"
        elif 'grtc' in l:
            data["Type"] = "FPRTC"
        return True
    return False

def parse_email_message_headers_only(msg, batch_id):
    """Parse only headers for the main fast-listing (used when fetching headers)."""
    raw_date = msg.get("Date", "")
    from_header = decode_mime_words(msg.get("From", ""))

    display_name = "-"
    domain = "-"

    # parse "Display Name <local@domain>"
    if "<" in from_header and "@" in from_header:
        try:
            display_name = from_header.split("<")[0].strip().strip('"')
            email_part = from_header.split("<")[1].split(">")[0]
            domain = email_part.split("@")[1].lower()
        except Exception:
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

    # search known auth tokens in headers string
    headers_str = ''.join(f"{h}: {v}\n" for h, v in msg.items())
    spf_m = re.search(r'spf=(\w+)', headers_str, re.I)
    dkim_m = re.search(r'dkim=(\w+)', headers_str, re.I)
    dmarc_m = re.search(r'dmarc=(\w+)', headers_str, re.I)
    if spf_m:
        data["SPF"] = spf_m.group(1).lower()
    if dkim_m:
        data["DKIM"] = dkim_m.group(1).lower()
    if dmarc_m:
        data["DMARC"] = dmarc_m.group(1).lower()

    # try to extract sub id from headers (fallback)
    if not extract_id_details(headers_str, data):
        for h, v in msg.items():
            if not v:
                continue
            parts = str(v).split('_')
            for part in parts:
                if len(part) < 20:
                    continue
                try:
                    padded = part + '=' * (-len(part) % 4)
                    dec = base64.b64decode(padded)
                    dec_s = dec.decode('utf-8', errors='ignore')
                    if extract_id_details(dec_s, data):
                        break
                except Exception:
                    pass
            if data["Type"] != "-":
                break

    return data

# ---------------- IMAP FETCH (with incremental UID) ----------------

def fetch_emails(start_date, end_date, mailbox="inbox", use_uid_since=False, last_uid=None, batch_id=0):
    """Fetch headers using UID search to keep it fast and incremental."""
    results = []
    s = start_date.strftime("%d-%b-%Y")
    e = (end_date + datetime.timedelta(days=1)).strftime("%d-%b-%Y")

    new_last_uid = last_uid
    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_input, password_input)
        imap.select(mailbox)

        if mailbox.lower() == "inbox" and use_uid_since and last_uid:
            criteria = f'(UID {int(last_uid)+1}:* SINCE {s} BEFORE {e})'
        else:
            criteria = f'(SINCE {s} BEFORE {e})'

        status, data = imap.uid('search', None, criteria)
        if status != 'OK' or not data or not data[0]:
            imap.logout()
            return pd.DataFrame(results, columns=DF_COLS), new_last_uid

        uids = data[0].split()
        for uid in uids:
            uid_decoded = uid.decode()
            status2, msg_parts = imap.uid('fetch', uid, '(BODY.PEEK[HEADER])')
            if status2 != 'OK':
                continue
            for part in msg_parts:
                if isinstance(part, tuple):
                    msg = email.message_from_bytes(part[1])
                    d = parse_email_message_headers_only(msg, batch_id)
                    d["Mailbox"] = "Inbox" if mailbox.lower() == "inbox" else "Spam"
                    results.append(d)

            # update latest uid for inbox so next incremental fetch picks up only new UID
            if mailbox.lower() == "inbox":
                new_last_uid = max(new_last_uid, uid_decoded) if new_last_uid else uid_decoded

        imap.logout()
    except imaplib.IMAP4.error as e:
        st.error(f"IMAP error fetching from {mailbox}: {e}")
    except Exception as e:
        st.error(f"General error fetching from {mailbox}: {e}")

    return pd.DataFrame(results, columns=DF_COLS), new_last_uid

# ---------------- CONCAT & DEDUP ----------------

def process_fetch_results(new_df, new_uid, target_df):
    """Concatenate new_df on top of target_df while deduping Message-ID and keeping newest batches first."""
    if new_df is None or new_df.empty:
        return target_df, 0, new_uid

    if not target_df.empty:
        seen = set(target_df["Message-ID"].dropna())
        new_df = new_df[~new_df["Message-ID"].isin(seen)].copy()

    if not new_df.empty:
        combined = pd.concat([new_df, target_df], ignore_index=True)
        combined = combined.sort_values(by='Batch_ID', ascending=False, ignore_index=True)
        return combined, len(new_df), new_uid

    return target_df, 0, new_uid

# ---------------- STYLING / HIGHLIGHTING ----------------

def _make_interleaved_palette():
    palette_a = ['#E3F2FD', '#E8F5E9', '#FFF3E0', '#F3E5F5']  # blue, green, orange, purple
    palette_b = ['#FFFDE7', '#E0F7FA', '#ECEFF1', '#E0F2F1']  # yellow, cyan, grey, teal
    interleaved = []
    for i in range(max(len(palette_a), len(palette_b))):
        if i < len(palette_a):
            interleaved.append(palette_a[i])
        if i < len(palette_b):
            interleaved.append(palette_b[i])
    return interleaved

_BATCH_PALETTE = _make_interleaved_palette()

def get_batch_color(batch_id):
    if not batch_id or pd.isna(batch_id) or int(batch_id) == 0:
        return ''
    idx = (int(batch_id)-1) % len(_BATCH_PALETTE)
    return f'background-color: {_BATCH_PALETTE[idx]}'

def highlight_main_table(row):
    spf = str(row.get('SPF', '')).lower()
    dkim = str(row.get('DKIM', '')).lower()
    dmarc = str(row.get('DMARC', '')).lower()
    failed = (spf != 'pass') or (dkim != 'pass') or (dmarc != 'pass')
    if failed:
        style = 'background-color: rgba(255, 0, 0, 0.18)'
        return [style] * len(row)
    return [get_batch_color(row.get('Batch_ID', 0))] * len(row)

def highlight_failed_auth(row):
    style = 'background-color: rgba(255, 0, 0, 0.18)'
    return [style] * len(row)

# ---------------- ACTION BUTTONS ----------------
colA, colB = st.columns([1.5, 2])

# Button labels respect whether we already have data (incremental vs initial)
if st.session_state.df.empty:
    initial_text = "📥 Fetch Emails"
else:
    initial_text = "🔄 Fetch New Emails"

with colA:
    if st.button(initial_text, help="Fetch emails for the selected date range (incremental when possible)."):
        st.session_state.batch_counter += 1
        current_batch = st.session_state.batch_counter
        use_uid_fetch = (not st.session_state.df.empty) and (st.session_state.last_uid is not None)

        with st.spinner(f"Fetching (Batch #{current_batch})..."):
            inbox_df, new_uid = fetch_emails(
                START_DATE, END_DATE, mailbox="inbox",
                use_uid_since=use_uid_fetch,
                last_uid=st.session_state.last_uid,
                batch_id=current_batch
            )
            spam_df, _ = fetch_emails(
                START_DATE, END_DATE, mailbox="[Gmail]/Spam",
                use_uid_since=False,
                last_uid=None,
                batch_id=current_batch
            )
            df_new = pd.concat([inbox_df, spam_df], ignore_index=True) if (not inbox_df.empty or not spam_df.empty) else pd.DataFrame(columns=DF_COLS)

            st.session_state.df, fetched_count, st.session_state.last_uid = process_fetch_results(df_new, new_uid, st.session_state.df)

            if fetched_count > 0:
                st.success(f"✅ Fetched {fetched_count} new emails (Batch #{current_batch}).")
            else:
                st.info("No new unique emails found.")

with colB:
    if st.button("🗑️ Fetch Spam Only", help="Fetch unique messages from Spam folder for the date range."):
        st.session_state.batch_counter += 1
        current_batch = st.session_state.batch_counter
        with st.spinner("Fetching spam folder..."):
            spam_df_new, _ = fetch_emails(START_DATE, END_DATE, mailbox="[Gmail]/Spam", use_uid_since=False, last_uid=None, batch_id=current_batch)
            st.session_state.spam_df, fetched_count, _ = process_fetch_results(spam_df_new, None, st.session_state.spam_df)
            if fetched_count > 0:
                st.success(f"✅ Added {fetched_count} unique spam emails (Batch #{current_batch}).")
            else:
                st.info("No new unique spam emails found.")

# ---------------- DISPLAY MAIN TABLE ----------------
st.subheader("📬 Processed Emails")

if not st.session_state.df.empty:
    inbox_cols = ["Subject", "Date", "From", "Domain", "SPF", "DKIM", "DMARC", "Type", "Sub ID", "Mailbox", "Batch_ID"]
    display_df = st.session_state.df.reindex(columns=inbox_cols, fill_value="-").copy()
    # index starting at 1
    display_df.index = range(1, len(display_df) + 1)
    styled = display_df.style.apply(highlight_main_table, axis=1)
    # Hide Batch_ID and Mailbox from column display if desired (we keep Mailbox visible in main table per original)
    st.dataframe(styled, use_container_width=True, column_config={"Batch_ID": None, "Message-ID": None})
else:
    st.info(f"No email data yet. Click '{initial_text}' to begin.")

# ---------------- FAILED AUTH TABLE ----------------
if not st.session_state.df.empty:
    failed = st.session_state.df[
        (st.session_state.df["SPF"] != "pass") |
        (st.session_state.df["DKIM"] != "pass") |
        (st.session_state.df["DMARC"] != "pass")
    ]
    if not failed.empty:
        st.subheader("❌ Failed Auth Emails")
        # include Sub ID and Date (with time)
        failed_cols = ["Subject", "Date", "From", "Domain", "SPF", "DKIM", "DMARC", "Type", "Sub ID"]
        failed_display = failed.reindex(columns=failed_cols, fill_value="-").copy()
        failed_display.index = range(1, len(failed_display) + 1)
        styled_failed = failed_display.style.apply(highlight_failed_auth, axis=1)
        st.dataframe(styled_failed, use_container_width=True)
    else:
        st.success("✅ All fetched emails passed SPF, DKIM, and DMARC.")

# ---------------- SPAM FOLDER DISPLAY ----------------
if not st.session_state.spam_df.empty:
    st.subheader("🚫 Spam Folder Emails")
    spam_cols = ["Subject", "Date", "From", "Domain", "Type", "Batch_ID"]
    display_spam_df = st.session_state.spam_df.reindex(columns=spam_cols, fill_value="-").copy()
    display_spam_df.index = range(1, len(display_spam_df) + 1)
    styled_spam = display_spam_df.style.apply(highlight_main_table, axis=1)
    st.dataframe(styled_spam, use_container_width=True, column_config={"Batch_ID": None})

# ---------------- DEEP TRACKING EXTRACTION (on demand) ----------------
st.markdown("---")
st.caption("🔬 Deep Tracking Extraction — opens when you click the button below")

if st.button("🔗 Deep Tracking Extraction"):
    st.session_state.show_tracking_tool = not st.session_state.show_tracking_tool

if st.session_state.show_tracking_tool:
    st.subheader("🔬 Deep Tracking Extraction")
    st.markdown("Paste the sender domains (one per line). Only messages whose parsed `Domain` contains any of these lines will be processed for link extraction.")
    domain_input = st.text_area("Paste domains (one per line)", height=140, placeholder="e.g. insuranceguidepoint.com\nassistupdategateway.com\nloansupportpath.com")
    col_run, col_help = st.columns([1, 3])
    with col_help:
        st.markdown("Rules:\n- `List-Unsubscribe` is taken *only* from headers (priority).\n- HTML unsubscribe detection checks common keywords (preferences, opt, optout, remove, checkout, deactivate, unsub, manage, rmv).\n- Logo is an img URL ending with .jpg/.png/.gif/.svg (and not a 1x1 pixel).\n- Open pixel is either img tag with width=1 or height=1 OR tracking-like endpoint (contains /res/ /ln/ /ref= /track /open).")
    with col_run:
        if st.button("Run Extraction"):

            if not domain_input.strip():
                st.info("Paste at least one domain to process.")
            else:
                selected_domains = [d.strip().lower() for d in domain_input.splitlines() if d.strip()]
                if not selected_domains:
                    st.info("No valid domains provided.")
                else:
                    results = []
                    try:
                        imap = imaplib.IMAP4_SSL("imap.gmail.com")
                        imap.login(email_input, password_input)
                        imap.select("inbox")
                    except Exception as e:
                        st.error(f"IMAP login error for deep extraction: {e}")
                        imap = None

                    if imap:
                        # iterate messages in session_state.df — we will fetch full body by Message-ID
                        for _, row in st.session_state.df.iterrows():
                            parsed_domain = str(row.get("Domain", "")).lower()
                            # simple containment check (handles ri.insurance..., subdomains)
                            if not any(sd in parsed_domain for sd in selected_domains):
                                continue

                            msg_mid = row.get("Message-ID")
                            if not msg_mid:
                                continue

                            # search for message by Message-ID header
                            try:
                                status, data = imap.search(None, f'(HEADER Message-ID "{msg_mid}")')
                                if status != 'OK' or not data or not data[0]:
                                    # try alternative search using SUBJECT + DATE as fallback
                                    continue
                                ids = data[0].split()
                                if not ids:
                                    continue
                                msg_id = ids[0]
                                status2, msg_parts = imap.fetch(msg_id, '(RFC822)')
                                if status2 != 'OK' or not msg_parts:
                                    continue
                                # msg_parts contains tuples; find the tuple with bytes
                                full_msg = None
                                for part in msg_parts:
                                    if isinstance(part, tuple):
                                        full_msg = email.message_from_bytes(part[1])
                                        break
                                if full_msg is None:
                                    continue

                                # ----- LIST-UNSUB FROM HEADERS (PRIORITY) -----
                                list_unsub = "-"
                                lu_headers = full_msg.get_all("List-Unsubscribe", [])
                                if lu_headers:
                                    combined = " ".join([decode_mime_words(h) for h in lu_headers])
                                    candidate_urls = re.findall(r'https?://[^\s,<>"]+', combined)
                                    if candidate_urls:
                                        list_unsub = candidate_urls[0]

                                # ----- GET HTML BODY (decode and clean) -----
                                html_body = ""
                                # try multipart search
                                if full_msg.is_multipart():
                                    for part in full_msg.walk():
                                        ctype = part.get_content_type()
                                        if ctype == "text/html":
                                            payload = part.get_payload(decode=True)
                                            if payload:
                                                try:
                                                    html_body = payload.decode(errors="ignore")
                                                except Exception:
                                                    html_body = str(payload)
                                                break
                                else:
                                    if full_msg.get_content_type() == "text/html":
                                        payload = full_msg.get_payload(decode=True)
                                        if payload:
                                            try:
                                                html_body = payload.decode(errors="ignore")
                                            except Exception:
                                                html_body = str(payload)

                                if not html_body:
                                    # nothing to scan in HTML
                                    continue

                                # ---- CLEAN quoted-printable artifacts ----
                                # remove soft line breaks added by quoted-printable
                                html_body = re.sub(r'=\r?\n', '', html_body)
                                # fix '=3D' encoded '='
                                html_body = html_body.replace('=3D', '=')
                                # fix rogue spaces after equals (do not remove '=' itself)
                                html_body = re.sub(r'=\s+', '=', html_body)

                                # ----- EXTRACT LINKS & IMAGES from HTML -----
                                # full <a href="..."> links
                                a_links = re.findall(r'<a[^>]+href=["\'](https?://[^"\'>\s]+)["\']', html_body, re.I)
                                # full <img ... src="..."> tags and capture entire tag too
                                img_matches = re.findall(r'(<img[^>]+>)', html_body, re.I)
                                img_links = []
                                # extract src and attributes from each img tag
                                for img_tag in img_matches:
                                    src_m = re.search(r'src=["\'](https?://[^"\'>\s]+)["\']', img_tag, re.I)
                                    if src_m:
                                        src = src_m.group(1)
                                        img_links.append((src, img_tag))  # keep tag for attr inspection

                                # Filter links to those that contain any of the selected domains OR the tracking domain from header
                                # If header list_unsub produced an explicit tracking domain, use it as one of the allowed filters too
                                tracking_domain_from_header = "-"
                                try:
                                    if list_unsub and list_unsub != "-":
                                        tracking_domain_from_header = urllib.parse.urlparse(list_unsub).netloc.lower()
                                except Exception:
                                    tracking_domain_from_header = "-"

                                def allowed_link(l):
                                    low = l.lower()
                                    if any(sd in low for sd in selected_domains):
                                        return True
                                    if tracking_domain_from_header and tracking_domain_from_header != "-" and tracking_domain_from_header in low:
                                        return True
                                    return False

                                a_links = [l for l in a_links if allowed_link(l)]
                                img_links = [(src, tag) for (src, tag) in img_links if allowed_link(src)]

                                # ----- CLASSIFY LINKS -----
                                # unsubscribe heuristics
                                unsub = "-"
                                UNSUB_KEYS = ["preferences","manage","dropout","rmv","checkout","opt","optout","remove","unsub","deactivate"]
                                for link in a_links:
                                    low = link.lower()
                                    if any(k in low for k in UNSUB_KEYS) or ('?' in urllib.parse.urlparse(low).query and any(k in low for k in ['opt','remove','unsub','deactivate'])):
                                        unsub = link
                                        break

                                # logo detection: img URL with image ext and not 1x1
                                logo = "-"
                                pixel = "-"
                                for (src, tag) in img_links:
                                    low = src.lower()
                                    # check for explicit width/height attributes in tag for pixel detection
                                    is_1x1 = bool(re.search(r'width\s*=\s*["\']?1["\']?', tag, re.I) or re.search(r'height\s*=\s*["\']?1["\']?', tag, re.I))
                                    if re.search(r'\.(jpg|jpeg|png|gif|svg)(\?|$)', low) and not is_1x1:
                                        # prefer larger logos with width > 1 (we don't parse numeric value for >1 here, but 1x1 is special-cased)
                                        if logo == "-":
                                            logo = src
                                        else:
                                            # keep first logo
                                            pass
                                    elif is_1x1 or any(k in low for k in ['/res/','/ln/','/ref=','/track','/open','/pixel']):
                                        # treat as pixel
                                        if pixel == "-":
                                            pixel = src
                                # safety fallbacks
                                if logo == "-" and img_links:
                                    # if any img has image ext pick the first
                                    for src, tag in img_links:
                                        if re.search(r'\.(jpg|jpeg|png|gif|svg)(\?|$)', src.lower()):
                                            logo = src
                                            break

                                if pixel == "-" and img_links:
                                    # pick last img if nothing else
                                    pixel = img_links[-1][0]

                                # tracking domain: prefer domain parsed from List-Unsubscribe header if present, otherwise fallback to parsed domain from Row Domain
                                tracking_domain = tracking_domain_from_header if (tracking_domain_from_header and tracking_domain_from_header != "-") else parsed_domain

                                results.append({
                                    "Subject": row.get("Subject"),
                                    "Date": row.get("Date"),
                                    "From": row.get("From"),
                                    "Sender Domain": row.get("Domain"),
                                    "Tracking Domain": tracking_domain,
                                    "List-Unsubscribe": list_unsub,
                                    "Unsubscribe Link": unsub,
                                    "Open Pixel": pixel,
                                    "Logo": logo
                                })

                            except Exception as e:
                                # continue processing next message if one fails
                                continue

                        try:
                            imap.logout()
                        except Exception:
                            pass

                    # show results
                    if results:
                        df_links = pd.DataFrame(results)
                        df_links.index = range(1, len(df_links) + 1)
                        st.subheader("📊 Tracking Link Results (selected domains)")
                        st.dataframe(df_links, use_container_width=True)
                    else:
                        st.info("No matching domain links found for the provided domains or no HTML body present.")

# ---------------- END APP ----------------
