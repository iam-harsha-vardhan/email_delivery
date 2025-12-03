# Inbox Creative Fetcher — Multi-account, signature-based aggregation (v2)
# Updated: removed the days-window concept entirely. Now the app:
# - Fetches the last N messages per account (Max messages per account) — newest first
# - Aggregates unique creatives by (Subject + Display + HTML) signature
# - Shows an Aggregate Variation table with: Subject, Display, Has HTML, Preview (render), Accounts Count, Accounts List
# - Also shows the Per-account raw table beneath (UID, Subject, Display, Date, Has HTML)
# - "Max messages per account" controls how many recent messages are fetched from each account; no date filtering.

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

# ---------- Page ----------
st.set_page_config(page_title="Inbox Creative Fetcher — MultiAccount Table v2", layout="wide")
st.title("📥 Multi-account Inbox Creative Finder (fetch last N messages per account)")

# ---------- Config ----------
UID_SCAN_LIMIT = 2000  # max UIDs to consider per account when searching (safety)
DEFAULT_MAX_MESSAGES = 200

# ---------- Helpers ----------
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
    try:
        text = quopri.decodestring(text.encode('utf-8', errors='ignore')).decode('utf-8', errors='ignore')
    except Exception:
        pass
    return text

def strip_html_tags(html_text):
    if not html_text: return ''
    html_text = re.sub(r'(?is)<(script|style).*?>.*?</\1>', ' ', html_text)
    text = re.sub(r'<[^>]+>', ' ', html_text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def extract_subject_display_html_from_msg(msg):
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
        sentences = re.split(r'(?<=[\.!?])\s+', stripped)
        display = ' '.join([s for s in sentences if s.strip()][:3]) or '-'

    if found_html:
        html_clean = re.sub(r'\s+', ' ', found_html).strip()
        return subject, display, html_clean
    else:
        return subject, display, '-'

def copy_button_html(text, key=None):
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

def make_signature(subject, display, html_text):
    key = (subject or '') + '\n||\n' + (display or '') + '\n||\n' + (html_text or '')
    return hashlib.sha256(key.encode('utf-8')).hexdigest()

# ---------- IMAP fetch per-account (last N messages) ----------

def fetch_last_n_for_account(email_addr, password, domain_substring, max_messages=DEFAULT_MAX_MESSAGES, uid_scan_limit=UID_SCAN_LIMIT):
    """Fetches the last up to max_messages messages for this account that have the domain_substring in From header.
    Returns list of dict rows with Account, UID, Subject, Display, HTML, Date."""
    rows = []
    try:
        imap = imaplib.IMAP4_SSL('imap.gmail.com')
        imap.login(email_addr.strip(), password.strip())
        imap.select('inbox')

        # search ALL and take latest uid_scan_limit UIDs then take newest max_messages
        status, data = imap.uid('search', None, 'ALL')
        if status != 'OK' or not data or not data[0]:
            imap.logout()
            return rows
        all_uids = data[0].split()
        if not all_uids:
            imap.logout()
            return rows

        # limit uids considered
        uids_to_check = all_uids[-uid_scan_limit:] if len(all_uids) > uid_scan_limit else all_uids

        count = 0
        # iterate newest first
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
                if domain_substring and domain_substring.lower() not in from_h.lower():
                    continue

                # fetch full body
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
                    formatted_date = parsedate_to_datetime(raw_date).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%d-%b-%Y %I:%M %p')
                except Exception:
                    formatted_date = raw_date

                rows.append({
                    'Account': email_addr,
                    'UID': uid_str,
                    'Subject': subject,
                    'Display': display,
                    'HTML': html_creative,
                    'Date': formatted_date
                })
                count += 1
            except Exception:
                continue

        imap.logout()
    except imaplib.IMAP4.error as e:
        st.error(f'IMAP error for {email_addr}: {e}')
        return rows
    except Exception as e:
        st.error(f'Error fetching {email_addr}: {e}')
        return rows

    return rows

# ---------- UI ----------
st.markdown('### 🔎 Input — Fetch last N messages per account (no days window)')
st.info('Removed days window. The app will fetch the last N messages per account (newest first). Use the "Domain" field to filter by From header substring (optional).')

# credentials editor
if 'creds_df' not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{'Email':'','Password':''}])

edited = st.data_editor(st.session_state.creds_df, num_rows='dynamic', use_container_width=True, hide_index=True)
st.session_state.creds_df = edited

col_a, col_b = st.columns([2,1])
with col_a:
    domain_input = st.text_input('Domain substring to filter From header (optional, e.g. example.com)', value='')
with col_b:
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
            st.info(f'Fetching last {max_msgs} messages for {acct}...')
            rows = fetch_last_n_for_account(acct, pwd, domain_input.strip(), max_messages=max_msgs)
            all_rows.extend(rows)
            progress.progress(int(((i+1)/total)*100))

        if not all_rows:
            st.info('No messages found for provided accounts / domain.')
        else:
            raw_df = pd.DataFrame(all_rows)

            # Aggregate by signature
            agg = {}
            for _, r in raw_df.iterrows():
                sig = make_signature(r['Subject'], r['Display'], r['HTML'])
                if sig not in agg:
                    agg[sig] = {
                        'Subject': r['Subject'],
                        'Display': r['Display'],
                        'HTML': r['HTML'],
                        'Accounts': set([r['Account']]),
                        'UIDs': {r['Account']: r['UID']},
                        'Dates': [r['Date']]
                    }
                else:
                    agg[sig]['Accounts'].add(r['Account'])
                    agg[sig]['UIDs'][r['Account']] = r['UID']
                    agg[sig]['Dates'].append(r['Date'])

            agg_rows = []
            for sig, v in agg.items():
                agg_rows.append({
                    'Signature': sig,
                    'Subject': v['Subject'],
                    'Display': v['Display'],
                    'Has_HTML': bool(v['HTML'] and v['HTML'] != '-'),
                    'Accounts_Count': len(v['Accounts']),
                    'Accounts_List': ', '.join(sorted(v['Accounts'])),
                    'HTML': v['HTML']
                })

            agg_df = pd.DataFrame(agg_rows)

            # Show Aggregate Variations table (full-width)
            st.markdown('## Aggregate Variations (unique Subject+Display+HTML)')
            if not agg_df.empty:
                agg_display = agg_df[['Signature','Subject','Display','Has_HTML','Accounts_Count','Accounts_List']].copy()
                agg_display = agg_display.rename(columns={'Has_HTML':'Has HTML?','Accounts_Count':'# Accounts','Accounts_List':'Accounts'})
                agg_display.index = range(1, len(agg_display)+1)
                st.dataframe(agg_display, use_container_width=True)

                # Preview selector
                options = [f"{i} — {agg_display.loc[i,'Subject'][:80]} — {agg_display.loc[i,'# Accounts']} accounts" for i in agg_display.index]
                sig_map = {options[idx]: agg_df.iloc[idx]['Signature'] for idx in range(len(options))}

                selected = st.multiselect('Select variations to preview', options=options)
                if selected:
                    st.markdown('### Previews for selected variations')
                    for sel in selected:
                        sig = sig_map[sel]
                        row = agg_df[agg_df['Signature'] == sig].iloc[0]
                        st.markdown(f"**{row['Subject']}** — Accounts: {row['Accounts_List']} — Has HTML: {row['Has_HTML']}")
                        if row['HTML'] and row['HTML'] != '-':
                            components.html(row['HTML'], height=480, scrolling=True)
                            st.markdown('**Copy HTML**')
                            components.html(copy_button_html(row['HTML'], key=row['Signature']), height=60)
                        else:
                            st.write('No HTML to render for this variation')
                        st.markdown('---')
            else:
                st.info('No aggregate variations found')

            # Show per-account raw table (spaced, full-width)
            st.markdown('## Per-account Raw Messages')
            raw_display = raw_df[['Account','UID','Subject','Display','Date']].copy()
            raw_display['Has HTML?'] = raw_df['HTML'].apply(lambda x: bool(x and x != '-'))
            raw_display = raw_display[['Account','UID','Subject','Display','Date','Has HTML?']]
            raw_display.index = range(1, len(raw_display)+1)
            st.dataframe(raw_display, use_container_width=True)

            st.success('Finished fetching and building tables.')

st.markdown('---')
st.caption('Notes: The app no longer uses a date window. It fetches the most recent messages (newest-first) up to the "Max messages per account" limit. Creatives are grouped by exact match of Subject+Display+HTML. If you want fuzzy grouping (e.g., ignore minor HTML differences), I can add a similarity threshold next.')
