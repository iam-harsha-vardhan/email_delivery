# app.py - Inbox Creative Fetcher (Full working code)
# Streamlit app: fetch Subject, Display snippet, and HTML creative by From-domain (last N days)
# Requirements: streamlit, pandas, pytz (pip install streamlit pandas pytz)

import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
import datetime
import re
import pandas as pd
import pytz
import quopri
import html
import uuid
import streamlit.components.v1 as components

# ---------- Page ----------
st.set_page_config(page_title="Inbox Creative Fetcher", layout="wide")
st.title("📥 Fetch Subject / Display Snippet / HTML Preview by Domain")

# ---------- Config ----------
UID_SCAN_LIMIT = 2000      # how many recent UIDs to scan when using SINCE
DEFAULT_DAYS = 30
DEFAULT_MAX_MESSAGES = 200

# ---------- Helper utilities ----------
def decode_mime_words(s):
    if not s: return ""
    decoded = ''
    for word, enc in decode_header(s):
        if isinstance(word, bytes):
            try:
                decoded += word.decode(enc or 'utf-8', errors='ignore')
            except Exception:
                decoded += word.decode('utf-8', errors='ignore')
        else:
            decoded += word
    return decoded.strip()

def safe_decode_bytes(b, charset=None):
    if b is None: return ''
    try:
        if charset:
            return b.decode(charset, errors='ignore')
        return b.decode('utf-8', errors='ignore')
    except Exception:
        try:
            return b.decode('latin-1', errors='ignore')
        except Exception:
            return str(b)

def try_decode_payload(part):
    payload = part.get_payload(decode=True)
    if payload is None:
        return ''
    try:
        charset = part.get_content_charset()
    except Exception:
        charset = None
    text = safe_decode_bytes(payload, charset)
    # attempt to clean quoted-printable remnants
    try:
        text = quopri.decodestring(text.encode('utf-8', errors='ignore')).decode('utf-8', errors='ignore')
    except Exception:
        pass
    return text

def strip_html_tags(html_text):
    if not html_text: return ''
    # remove scripts/styles (just in case) and tags, unescape entities
    html_text = re.sub(r'(?is)<(script|style).*?>.*?</\1>', ' ', html_text)
    text = re.sub(r'<[^>]+>', ' ', html_text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def extract_subject_display_html_from_msg(msg):
    """
    Returns (subject, display_snippet, html_creative_or_dash)
    - display_snippet prefers text/plain (first ~3 lines) otherwise derives from stripped HTML
    - html_creative is decoded HTML string or '-' if none
    """
    subject = decode_mime_words(msg.get('Subject','No Subject'))
    found_html = None
    found_plain = None
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get('Content-Disposition',''))
                if ctype == 'text/html' and 'attachment' not in disp.lower():
                    found_html = try_decode_payload(part)
                elif ctype == 'text/plain' and 'attachment' not in disp.lower():
                    found_plain = try_decode_payload(part)
        else:
            ctype = msg.get_content_type()
            if ctype == 'text/html':
                found_html = try_decode_payload(msg)
            elif ctype == 'text/plain':
                found_plain = try_decode_payload(msg)
    except Exception:
        pass

    display = '-'
    if found_plain:
        lines = [l.strip() for l in found_plain.splitlines() if l.strip()][:3]
        if lines:
            display = ' '.join(lines)
    elif found_html:
        stripped = strip_html_tags(found_html)
        sentences = re.split(r'(?<=[\.\?!])\s+', stripped)
        display = ' '.join([s for s in sentences if s.strip()][:3]) or '-'

    if found_html:
        html_clean = re.sub(r'\s+', ' ', found_html).strip()
        return subject, display, html_clean
    else:
        return subject, display, '-'

def copy_button_html(text, key=None):
    """Return a small HTML snippet with a copy-to-clipboard button using the full HTML text."""
    if key is None:
        key = str(uuid.uuid4())
    safe_text = html.escape(text)
    snippet = f"""
    <div style="display:inline-block">
      <button id="copy_btn_{key}">Copy HTML</button>
      <script>
        const btn = document.getElementById("copy_btn_{key}");
        btn.onclick = () => {{
          const text = `{safe_text}`;
          navigator.clipboard.writeText(text).then(()=>{{ btn.innerText='Copied'; setTimeout(()=>{{btn.innerText='Copy HTML';}},1200); }}).catch(()=>{{
            const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select();
            try{{ document.execCommand('copy'); btn.innerText='Copied'; setTimeout(()=>{{btn.innerText='Copy HTML';}},1200); }}catch(e){{ alert('Copy failed'); }}
            document.body.removeChild(ta);
          }});
        }};
      </script>
    </div>
    """
    return snippet

# ---------- IMAP fetch function ----------
def fetch_subject_display_html_by_domain(email_addr, password, domain, days_window=DEFAULT_DAYS, max_messages=DEFAULT_MAX_MESSAGES, uid_scan_limit=UID_SCAN_LIMIT):
    """
    Connect to Gmail IMAP, search messages SINCE cutoff (days_window), filter by domain in From,
    fetch the full body for matched messages, and return DataFrame with columns:
    UID, Subject, Display, HTML, Date
    """
    results = []
    try:
        imap = imaplib.IMAP4_SSL('imap.gmail.com')
        imap.login(email_addr.strip(), password.strip())
        imap.select('inbox')

        ist = pytz.timezone('Asia/Kolkata')
        cutoff_dt = datetime.datetime.now(ist) - datetime.timedelta(days=int(days_window))
        cutoff_str = cutoff_dt.strftime('%d-%b-%Y')

        status, data = imap.uid('search', None, f'(SINCE "{cutoff_str}")')
        if status != 'OK' or not data or not data[0]:
            imap.logout()
            return pd.DataFrame(results)

        all_uids = data[0].split()
        if not all_uids:
            imap.logout()
            return pd.DataFrame(results)

        # Limit how many UIDs we check to avoid huge mailboxes
        uids_to_check = all_uids[-uid_scan_limit:] if len(all_uids) > uid_scan_limit else all_uids

        count = 0
        # iterate newest-first so max_messages fills quickly
        for i in range(len(uids_to_check)-1, -1, -1):
            if count >= max_messages:
                break
            uid = uids_to_check[i]
            uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
            try:
                r, md = imap.uid('fetch', uid_str, '(BODY.PEEK[HEADER.FIELDS (FROM DATE SUBJECT)])')
                if r != 'OK' or not md:
                    continue
                hdr_part = None
                for part in md:
                    if isinstance(part, tuple):
                        hdr_part = part[1]
                        break
                if not hdr_part:
                    continue
                msg_hdr = email.message_from_bytes(hdr_part)
                from_h = decode_mime_words(msg_hdr.get('From',''))
                # filter by domain substring in From header
                if domain.lower() not in from_h.lower():
                    continue

                # fetch the full body (we need HTML)
                r2, md2 = imap.uid('fetch', uid_str, '(BODY.PEEK[])')
                if r2 != 'OK' or not md2:
                    continue
                raw_msg_bytes = None
                for p in md2:
                    if isinstance(p, tuple) and p[1]:
                        raw_msg_bytes = p[1]
                        break
                if not raw_msg_bytes:
                    continue

                try:
                    msg = email.message_from_bytes(raw_msg_bytes)
                except Exception:
                    continue

                subject, display, html_creative = extract_subject_display_html_from_msg(msg)

                raw_date = msg.get('Date','')
                formatted_date = raw_date
                try:
                    # format to IST readable
                    formatted_date = parsedate_to_datetime(raw_date).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%d-%b-%Y %I:%M %p')
                except Exception:
                    formatted_date = raw_date

                results.append({
                    'UID': uid_str,
                    'Subject': subject,
                    'Display': display,
                    'HTML': html_creative,
                    'Date': formatted_date
                })
                count += 1
            except Exception:
                # ignore per-message errors, continue
                continue

        imap.logout()
    except imaplib.IMAP4.error as e:
        st.error(f'IMAP error for {email_addr}: {e}')
        return pd.DataFrame(results)
    except Exception as e:
        st.error(f'Error fetching {email_addr}: {e}')
        return pd.DataFrame(results)

    return pd.DataFrame(results)

# ---------- UI ----------
st.markdown("### 🔎 Input — Domain + Date window")
col1, col2, col3 = st.columns([2,1,1])
with col1:
    domain_input = st.text_input('Domain to filter (e.g. example.com)', value='')
with col2:
    days = st.number_input('Days window', min_value=1, max_value=3650, value=DEFAULT_DAYS, step=1)
with col3:
    max_msgs = st.number_input('Max messages', min_value=1, max_value=2000, value=DEFAULT_MAX_MESSAGES, step=1)

st.info("Provide a Gmail account (App Password recommended) — the app searches the chosen inbox for messages whose From header contains the domain you supply.")

# credentials editor (small)
if 'creds_df' not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{'Email':'','Password':''}])

colc1, colc2 = st.columns([3,1])
with colc1:
    edited = st.data_editor(st.session_state.creds_df, num_rows='dynamic', use_container_width=True, hide_index=True)
    st.session_state.creds_df = edited

with colc2:
    if st.button('Fetch & Preview'):
        creds = [r for _,r in st.session_state.creds_df.iterrows() if r.get('Email','').strip() and r.get('Password','').strip()]
        if not creds:
            st.error('Please provide at least one account with app password.')
        elif not domain_input.strip():
            st.error('Provide a domain to filter by (e.g. example.com)')
        else:
            acct = creds[0]
            with st.spinner('Fetching and rendering previews — beware large mailboxes...'):
                df = fetch_subject_display_html_by_domain(acct['Email'], acct['Password'], domain_input.strip(), days_window=days, max_messages=max_msgs)
                if df.empty:
                    st.info('No matching messages found in the date window.')
                else:
                    st.subheader(f'Results — {len(df)} message(s)')
                    # present compact rows: Subject | Display | Rendered preview | Copy HTML
                    for idx, row in df.iterrows():
                        subj = row['Subject']
                        disp = row['Display']
                        html_code = row['HTML']
                        date_str = row.get('Date','-')

                        st.markdown(f"**{subj}**  ")
                        st.markdown(f"*{date_str}* — {disp}")
                        cols = st.columns([1.2,1,0.8])
                        with cols[0]:
                            st.write("Preview (rendered)")
                            if html_code and html_code != '-':
                                # Render HTML — looks like browser. Be aware remote images/resources may load.
                                # Height chosen to display content; adjust if needed.
                                components.html(html_code, height=400, scrolling=True)
                            else:
                                st.write("No HTML creative available")
                        with cols[1]:
                            st.write("HTML (trimmed)")
                            truncated = (html_code[:800] + '...') if html_code and len(html_code) > 800 else html_code
                            st.text_area(f'html_{idx}', value=truncated if truncated else '-', height=160)
                        with cols[2]:
                            st.write("Copy")
                            if html_code and html_code != '-':
                                components.html(copy_button_html(html_code, key=row['UID']), height=60)
                            else:
                                st.write("—")
                        st.markdown("---")
                    st.success("Done fetching previews.")

st.markdown("---")
st.caption("Notes: This renders raw HTML from emails. If your creatives include remote images/resources they'll attempt to load in the preview. Increase `Max messages` or `Days window` carefully for large mailboxes.")
