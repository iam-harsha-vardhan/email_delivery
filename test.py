# app.py
# Inbox Creative Fetcher — Single Table (Display, Subject, HTML) + Preview & Copy (v3)
# Drop this file into your project and run `streamlit run app.py`.

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
import hashlib
import streamlit.components.v1 as components

st.set_page_config(page_title="Inbox Creative Fetcher — Single Table", layout="wide")
st.title("📥 Inbox Creative Fetcher — Single Table: Display, Subject, HTML")

# ---------- Config ----------
UID_SCAN_LIMIT = 2000
DEFAULT_MAX_MESSAGES = 20
BATCH_FETCH_SIZE = 100

# ---------- Helpers ----------
def decode_mime_words(s):
    if not s:
        return ""
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
    if b is None:
        return ''
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
    try:
        text = quopri.decodestring(text.encode('utf-8', errors='ignore')).decode('utf-8', errors='ignore')
    except Exception:
        pass
    return text


def strip_html_tags(html_text):
    if not html_text:
        return ''
    html_text = re.sub(r'(?is)<(script|style).*?>.*?</\\1>', ' ', html_text)
    text = re.sub(r'<[^>]+>', ' ', html_text)
    text = html.unescape(text)
    text = re.sub(r'\\s+', ' ', text).strip()
    return text


def extract_subject_display_html_from_msg(msg):
    subject = decode_mime_words(msg.get('Subject', 'No Subject'))
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
        sentences = re.split(r'(?<=[\\.!?])\\s+', stripped)
        display = ' '.join([s for s in sentences if s.strip()][:3]) or '-'

    if found_html:
        html_clean = re.sub(r'\\s+', ' ', found_html).strip()
        return subject, display, html_clean
    else:
        return subject, display, '-'


def make_signature(subject, display, html_text):
    key = (subject or '') + '\\n||\\n' + (display or '') + '\\n||\\n' + (html_text or '')
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def copy_button_html(text, key=None):
    if key is None:
        key = str(uuid.uuid4())
    safe_text = html.escape(text)
    return f"""
    <div style='display:flex; gap:8px; align-items:center'>
      <button id='copy_btn_{key}'>Copy HTML</button>
      <script>
        const btn = document.getElementById('copy_btn_{key}');
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

# ---------- IMAP optimized fetch ----------
def fetch_last_n_for_account_fast(email_addr, password, domain_substring, max_messages=DEFAULT_MAX_MESSAGES, uid_scan_limit=UID_SCAN_LIMIT):
    rows = []
    try:
        imap = imaplib.IMAP4_SSL('imap.gmail.com')
        imap.login(email_addr.strip(), password.strip())
        imap.select('inbox')

        # server-side search
        if domain_substring:
            try:
                status, data = imap.uid('search', None, 'FROM', f'"{domain_substring}"')
            except Exception:
                status, data = imap.uid('search', None, f'FROM "{domain_substring}"')
        else:
            status, data = imap.uid('search', None, 'ALL')

        if status != 'OK' or not data or not data[0]:
            imap.logout()
            return rows

        matched_uids = data[0].split()
        if not matched_uids:
            imap.logout()
            return rows

        candidate_uids = matched_uids[-uid_scan_limit:] if len(matched_uids) > uid_scan_limit else matched_uids
        selected_uids = candidate_uids[-int(max_messages):] if len(candidate_uids) > int(max_messages) else candidate_uids

        for i in range(0, len(selected_uids), BATCH_FETCH_SIZE):
            chunk = selected_uids[i:i+BATCH_FETCH_SIZE]
            uid_seq = b','.join(chunk)
            try:
                res, md = imap.uid('fetch', uid_seq, '(BODY.PEEK[])')
            except Exception:
                for u in chunk:
                    try:
                        u_str = u.decode()
                        r2, md2 = imap.uid('fetch', u_str, '(BODY.PEEK[])')
                        if r2 != 'OK' or not md2:
                            continue
                        raw_msg_bytes = None
                        for p in md2:
                            if isinstance(p, tuple) and p[1]:
                                raw_msg_bytes = p[1]
                                break
                        if not raw_msg_bytes:
                            continue
                        msg = email.message_from_bytes(raw_msg_bytes)
                        subject, display, html_creative = extract_subject_display_html_from_msg(msg)
                        raw_date = msg.get('Date','')
                        try:
                            formatted_date = parsedate_to_datetime(raw_date).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%d-%b-%Y %I:%M %p')
                        except Exception:
                            formatted_date = raw_date
                        rows.append({'Account': email_addr, 'UID': u_str, 'Subject': subject, 'Display': display, 'HTML': html_creative, 'Date': formatted_date})
                    except Exception:
                        continue
                continue

            for part in md:
                if not isinstance(part, tuple):
                    continue
                raw_msg_bytes = part[1]
                if not raw_msg_bytes:
                    continue
                try:
                    msg = email.message_from_bytes(raw_msg_bytes)
                except Exception:
                    continue
                uid_found = None
                try:
                    meta = part[0].decode('utf-8', errors='ignore')
                    m = re.search(r'UID\\s+(\\d+)', meta)
                    if m:
                        uid_found = m.group(1)
                except Exception:
                    uid_found = None
                uid_val = uid_found if uid_found else (chunk[0].decode() if chunk else '')
                subject, display, html_creative = extract_subject_display_html_from_msg(msg)
                raw_date = msg.get('Date','')
                try:
                    formatted_date = parsedate_to_datetime(raw_date).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%d-%b-%Y %I:%M %p')
                except Exception:
                    formatted_date = raw_date
                rows.append({'Account': email_addr, 'UID': uid_val, 'Subject': subject, 'Display': display, 'HTML': html_creative, 'Date': formatted_date})

        imap.logout()
    except imaplib.IMAP4.error as e:
        st.error(f'IMAP error for {email_addr}: {e}')
        return rows
    except Exception as e:
        st.error(f'Error fetching {email_addr}: {e}')
        return rows

    return rows

# ---------- UI ----------
st.markdown('### 🔎 Input — Fetch last N messages per account (fast IMAP search)')
st.info('Enter one or more accounts (Email + App Password). Optionally provide a domain substring to speed searching on the server.')

if 'creds_df' not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{'Email':'','Password':''}])

edited = st.data_editor(st.session_state.creds_df, num_rows='dynamic', use_container_width=True, hide_index=True)
st.session_state.creds_df = edited

col1, col2 = st.columns([2,1])
with col1:
    domain_input = st.text_input('Domain substring to filter FROM header (optional)', value='')
with col2:
    max_msgs = st.number_input('Max messages per account', min_value=1, max_value=2000, value=20, step=1)

if st.button('Fetch across accounts'):
    creds = [r for _,r in st.session_state.creds_df.iterrows() if r.get('Email','').strip() and r.get('Password','').strip()]
    if not creds:
        st.error('Please provide at least one account (Email + App password).')
    else:
        all_rows = []
        progress = st.progress(0)
        total = len(creds)
        for i, cred in enumerate(creds):
            acct = cred['Email'].strip()
            pwd = cred['Password'].strip()
            st.info(f'Fetching (fast) for {acct}...')
            rows = fetch_last_n_for_account_fast(acct, pwd, domain_input.strip(), max_messages=max_msgs)
            all_rows.extend(rows)
            progress.progress(int(((i+1)/total)*100))

        if not all_rows:
            st.info('No messages found.')
        else:
            raw_df = pd.DataFrame(all_rows)

            # aggregate by exact signature
            agg = {}
            for _, r in raw_df.iterrows():
                sig = make_signature(r['Subject'], r['Display'], r['HTML'])
                if sig not in agg:
                    agg[sig] = {'Subject': r['Subject'], 'Display': r['Display'], 'HTML': r['HTML'], 'Accounts': set([r['Account']])}
                else:
                    agg[sig]['Accounts'].add(r['Account'])

            # build single table rows
            table_rows = []
            for sig, v in agg.items():
                table_rows.append({'Display': v['Display'], 'Subject': v['Subject'], 'HTML': (v['HTML'] if v['HTML'] and v['HTML'] != '-' else ''), 'Accounts_Count': len(v['Accounts']), 'Accounts_List': ', '.join(sorted(v['Accounts'])) , 'Signature': sig})

            table_df = pd.DataFrame(table_rows)
            # trim HTML column for table to keep it compact
            table_df['HTML_trim'] = table_df['HTML'].apply(lambda x: (x[:300] + '...') if x and len(x) > 300 else x)

            # show table with only Display, Subject, HTML_trim, Accounts_Count
            display_df = table_df[['Display','Subject','HTML_trim','Accounts_Count']].copy()
            display_df = display_df.rename(columns={'HTML_trim':'HTML (trimmed)', 'Accounts_Count':'# Accounts'})
            display_df.index = range(1, len(display_df)+1)
            st.subheader('Results — Single Table')
            st.dataframe(display_df, use_container_width=True)

            # selector for previewing a row (preview area below)
            opts = [f"{i} — {display_df.loc[i,'Subject'][:80]} — {display_df.loc[i,'# Accounts']} accounts" for i in display_df.index]
            sel = st.selectbox('Select one variation to preview', options=['-- none --'] + opts, index=0)

            if sel and sel != '-- none --':
                left = sel.split(' — ')[0].strip()
                try:
                    idx = int(left)
                except Exception:
                    st.error('Could not parse selection')
                    idx = None

                if idx is not None:
                    chosen = table_df.iloc[idx-1]
                    st.markdown('### Preview (rendered)')
                    # copy button at the top of the preview box (single place, not per-table-row)
                    if chosen['HTML']:
                        st.markdown('**Copy HTML:**', unsafe_allow_html=True)
                        components.html(copy_button_html(chosen['HTML'], key=chosen['Signature']), height=60)
                    else:
                        st.write('No HTML for this variation')

                    # show accounts count and list
                    st.markdown(f"**Subject:** {chosen['Subject']}  \n**Display snippet:** {chosen['Display']}  \n**Accounts containing this creative:** {chosen['Accounts_Count']} — {chosen['Accounts_List']}")

                    # render HTML
                    if chosen['HTML']:
                        components.html(chosen['HTML'], height=480, scrolling=True)
                    st.markdown('---')

            st.success('Table ready. Pick a row to preview and copy HTML from the preview box above.')

st.markdown('---')
st.caption('This single table shows Display, Subject and a trimmed HTML column. Use the preview selector to render the full HTML and copy it (copy button appears above the preview).')
