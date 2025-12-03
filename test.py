# app.py
# Inbox Creative Fetcher — Optimized, full working script
# Run: streamlit run app.py
# Requirements: streamlit, pandas, pytz

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

st.set_page_config(page_title="Inbox Creative Fetcher — Optimized", layout="wide")
st.title("📥 Multi-account Inbox Creative Finder — Fast IMAP search")

# -------- CONFIG ----------
UID_SCAN_LIMIT = 2000
DEFAULT_MAX_MESSAGES = 20
BATCH_FETCH_SIZE = 100

# -------- HELPERS ----------
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
    html_text = re.sub(r'(?is)<(script|style).*?>.*?</\1>', ' ', html_text)
    text = re.sub(r'<[^>]+>', ' ', html_text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def extract_subject_display_html_from_msg(msg):
    """
    returns (subject, display_snippet, html_or_dash)
    """
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
        sentences = re.split(r'(?<=[\.\?!])\s+', stripped)
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

# -------- FAST IMAP FETCH (server-side search + limited fetch) ----------
def fetch_last_n_for_account_fast(email_addr, password, domain_substring, max_messages=DEFAULT_MAX_MESSAGES, uid_scan_limit=UID_SCAN_LIMIT):
    """
    Use IMAP UID SEARCH (FROM "domain") when domain_substring provided. Then fetch newest up to max_messages bodies.
    Returns list of dict rows: {Account, UID, Subject, Display, HTML, Date}
    """
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

        # Candidate safety limit and pick newest N
        candidate_uids = matched_uids[-uid_scan_limit:] if len(matched_uids) > uid_scan_limit else matched_uids
        selected_uids = candidate_uids[-int(max_messages):] if len(candidate_uids) > int(max_messages) else candidate_uids

        # Fetch in batches
        for i in range(0, len(selected_uids), BATCH_FETCH_SIZE):
            chunk = selected_uids[i:i+BATCH_FETCH_SIZE]
            uid_seq = b','.join(chunk)
            try:
                res, md = imap.uid('fetch', uid_seq, '(BODY.PEEK[])')
            except Exception:
                # fallback to per-UID fetch
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

            # parse returned tuples
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
                # try to extract UID from meta
                uid_found = None
                try:
                    meta = part[0].decode('utf-8', errors='ignore')
                    m = re.search(r'UID\s+(\d+)', meta)
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

# -------- UI layout ----------
st.markdown("### 🔎 Input — Fetch last N messages per account (server-side search)")
st.info("Provide one or more Gmail accounts (Email + App Password). If you supply a Domain substring the app will ask IMAP server to return messages whose FROM header contains that substring (fast). If left empty it searches ALL (slower).")

# credentials editor
if 'creds_df' not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{'Email':'','Password':''}])
edited = st.data_editor(st.session_state.creds_df, num_rows='dynamic', use_container_width=True, hide_index=True)
st.session_state.creds_df = edited

col_a, col_b = st.columns([2,1])
with col_a:
    domain_input = st.text_input('Domain substring to filter FROM header (optional, e.g. example.com)', value='')
with col_b:
    max_msgs = st.number_input('Max messages per account', min_value=1, max_value=2000, value=DEFAULT_MAX_MESSAGES, step=1)

if st.button('Fetch across accounts (fast)'):
    creds = [r for _, r in st.session_state.creds_df.iterrows() if r.get('Email','').strip() and r.get('Password','').strip()]
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
                latest_date = None
                try:
                    parsed = [parsedate_to_datetime(d) for d in v['Dates'] if d]
                    if parsed:
                        latest_dt = max(parsed)
                        latest_date = latest_dt.astimezone(pytz.timezone('Asia/Kolkata')).strftime('%d-%b-%Y %I:%M %p')
                except Exception:
                    latest_date = v['Dates'][0] if v['Dates'] else '-'

                agg_rows.append({
                    'Signature': sig,
                    'Subject': v['Subject'],
                    'Display': v['Display'],
                    'Date': latest_date or '-',
                    'Accounts_Present': ', '.join(sorted(list(v['Accounts']))),
                    'Has_HTML': bool(v['HTML'] and v['HTML'] != '-'),
                    'HTML': v['HTML'],
                    'UIDs': v['UIDs']
                })

            agg_df = pd.DataFrame(agg_rows)

            # ---------- SHOW AGGREGATE TABLE ----------
            st.markdown('## Aggregate Presence Table')
            if not agg_df.empty:
                disp = agg_df[['Signature','Subject','Display','Date','Accounts_Present','Has_HTML']].copy()
                disp = disp.rename(columns={'Accounts_Present':'Accounts', 'Has_HTML':'Has HTML?'})
                disp.index = range(1, len(disp)+1)
                st.dataframe(disp, use_container_width=True)

                # Selector to preview
                options = [f"{idx} — {disp.loc[idx,'Subject'][:80]} — {disp.loc[idx,'Date']}" for idx in disp.index]
                sig_map = {opt: agg_df.iloc[idx-1]['Signature'] for idx, opt in enumerate(options, start=1)}

                selected = st.multiselect('Select aggregate rows to preview', options=options)
                if selected:
                    st.markdown('### Preview selected aggregate creatives')
                    for sel in selected:
                        # parse index from option
                        left = sel.split(' — ')[0].strip()
                        try:
                            idx = int(left)
                        except Exception:
                            st.error('Invalid selection parsing index')
                            continue
                        row = agg_df.iloc[idx-1]
                        st.markdown(f"**{row['Subject']}** — *{row['Date']}*  \nAccounts: {row['Accounts_Present']}")
                        if row['HTML'] and row['HTML'] != '-':
                            components.html(row['HTML'], height=480, scrolling=True)
                            st.markdown('**Copy HTML**')
                            components.html(copy_button_html(row['HTML'], key=row['Signature']), height=60)
                        else:
                            st.write('No HTML available for this creative')
                        st.markdown('---')
            else:
                st.info('No aggregate rows to show')

            # ---------- SHOW PER-ACCOUNT RAW TABLE ----------
            st.markdown('## Per-account Raw Messages')
            raw_display = raw_df[['Account','UID','Subject','Display','Date','HTML']].copy()
            raw_display['Has HTML?'] = raw_display['HTML'].apply(lambda x: bool(x and x != '-'))
            raw_display = raw_display[['Account','UID','Subject','Display','Date','Has HTML?']]
            raw_display.index = range(1, len(raw_display)+1)
            st.dataframe(raw_display, use_container_width=True)

            st.success('Finished — aggregate and per-account tables are above.')

st.markdown('---')
st.caption('Matching creatives are grouped by SHA-256 signature of (Subject + Display + HTML). Server-side FROM search is used when you provide a domain substring; that speeds fetching significantly.')
