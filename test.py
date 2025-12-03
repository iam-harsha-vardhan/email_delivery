# Inbox Creative Fetcher — Multi-account, structured table, fixed 30-day window
# Features in this version:
# - REMOVED the Days window input (fixed to last 30 days internally)
# - Supports multiple accounts: you can add several credentials in the grid
# - Fetches from each account and builds two full-width tables:
#    1) **Aggregate Presence Table**: one row per unique creative (Subject+Display+HTML hash) with which accounts contain it
#    2) **Per-account Raw Table**: shows each account's captured messages (UID, Subject, Display, Date, Has HTML)
# - Previews: select rows from the Aggregate table to render the HTML creative and see which accounts have it
# - Copy HTML button included in preview

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
st.set_page_config(page_title="Inbox Creative Fetcher — MultiAccount Table", layout="wide")
st.title("📥 Multi-account Inbox Creative Finder (last 30 days)")

# ---------- Config (fixed) ----------
UID_SCAN_LIMIT = 2000
DEFAULT_DAYS_FIXED = 30   # fixed window — Days input removed per request
DEFAULT_MAX_MESSAGES = 200

# ---------- Helpers (same as before) ----------
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

# ---------- IMAP fetch (per-account) ----------

def fetch_for_account(email_addr, password, domain, days_window=DEFAULT_DAYS_FIXED, max_messages=DEFAULT_MAX_MESSAGES, uid_scan_limit=UID_SCAN_LIMIT):
    rows = []
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
            return rows
        all_uids = data[0].split()
        if not all_uids:
            imap.logout()
            return rows

        uids_to_check = all_uids[-uid_scan_limit:] if len(all_uids) > uid_scan_limit else all_uids
        count = 0
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
                if domain.lower() not in from_h.lower():
                    continue

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

# ---------- Aggregation helpers ----------

def make_signature(subject, display, html_text):
    """Create a stable signature (hash) for grouping identical creatives."""
    key = (subject or '') + '\n||\n' + (display or '') + '\n||\n' + (html_text or '')
    return hashlib.sha256(key.encode('utf-8')).hexdigest()

# ---------- UI ----------
st.markdown("### 🔎 Input — (fixed) Last 30 days — Multiple accounts supported")
st.info("Days window removed (fixed to last 30 days). Add multiple accounts below; each row should be Email + App Password for Gmail.")

# credentials editor
if 'creds_df' not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{'Email':'','Password':''}])

edited = st.data_editor(st.session_state.creds_df, num_rows='dynamic', use_container_width=True, hide_index=True)
st.session_state.creds_df = edited

col1, col2 = st.columns([3,1])
with col1:
    max_msgs = st.number_input('Max messages per account', min_value=10, max_value=2000, value=DEFAULT_MAX_MESSAGES, step=10)
with col2:
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
                st.info(f'Fetching for {acct}...')
                rows = fetch_for_account(acct, pwd, domain_input := (st.session_state.get('last_domain') if 'last_domain' in st.session_state else '' ) or st.text_input('Domain (enter before fetching)', value=''))
                # Note: domain_input must be provided via the small input above; we keep compatibility
                # but also store last used domain
                st.session_state['last_domain'] = domain_input
                all_rows.extend(rows)
                progress.progress(int(((i+1)/total)*100))

            # build per-account DataFrame
            if not all_rows:
                st.info('No messages found across accounts (check domain or credentials).')
            else:
                raw_df = pd.DataFrame(all_rows)

                # Build Aggregate presence map keyed by signature
                agg = {}
                for _, r in raw_df.iterrows():
                    sig = make_signature(r['Subject'], r['Display'], r['HTML'])
                    if sig not in agg:
                        agg[sig] = {
                            'Subject': r['Subject'],
                            'Display': r['Display'],
                            'HTML': r['HTML'],
                            'Dates': [r['Date']] if r.get('Date') else [],
                            'Accounts': set([r['Account']]),
                            'UIDs': {r['Account']: r['UID']}
                        }
                    else:
                        agg[sig]['Accounts'].add(r['Account'])
                        agg[sig]['Dates'].append(r.get('Date'))
                        agg[sig]['UIDs'][r['Account']] = r['UID']

                # Build aggregate DataFrame for display
                agg_rows = []
                for sig, v in agg.items():
                    latest_date = None
                    try:
                        # parse dates if possible, pick latest, else keep first
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

                # ---------- SHOW AGGREGATE TABLE (full-width) ----------
                st.markdown('## Aggregate Presence Table')
                if not agg_df.empty:
                    disp = agg_df[['Signature','Subject','Display','Date','Accounts_Present','Has_HTML']].copy()
                    disp = disp.rename(columns={'Accounts_Present':'Accounts', 'Has_HTML':'Has HTML?'})
                    disp.index = range(1, len(disp)+1)
                    st.dataframe(disp, use_container_width=True)

                    # Selector to preview
                    options = [f"{i} — {row.Subject[:70]} — {row.Date}" for i,row in agg_df.iterrows()]
                    sel = st.multiselect('Select aggregate rows to preview', options=options)
                    if sel:
                        st.markdown('### Preview selected aggregate creatives')
                        for s in sel:
                            idx = int(s.split(' — ')[0])
                            row = agg_df.iloc[idx]
                            st.markdown(f"**{row['Subject']}** — *{row['Date']}*  \nAccounts: {row['Accounts_Present']}")
                            # Render preview full-width (not side-by-side)
                            if row['HTML'] and row['HTML'] != '-':
                                components.html(row['HTML'], height=480, scrolling=True)
                                st.markdown('**Copy HTML**')
                                components.html(copy_button_html(row['HTML'], key=row['Signature']), height=60)
                            else:
                                st.write('No HTML available for this creative')
                            st.markdown('---')
                else:
                    st.info('No aggregate rows to show')

                # ---------- SHOW PER-ACCOUNT RAW TABLE (full-width, spaced) ----------
                st.markdown('## Per-account Raw Messages')
                st.write('This table lists the captured messages per account (UID, Subject, Display, Date, Has HTML).')
                raw_display = raw_df[['Account','UID','Subject','Display','Date','HTML']].copy()
                raw_display['Has HTML?'] = raw_display['HTML'].apply(lambda x: bool(x and x != '-'))
                raw_display = raw_display[['Account','UID','Subject','Display','Date','Has HTML?']]
                st.dataframe(raw_display.reset_index(drop=True), use_container_width=True)

                st.success('Finished — aggregate and per-account tables are above.')

# small note about how the "same creative in different accounts" is determined
st.markdown('---')
st.caption('How "same creative" is determined: we group messages by the SHA-256 signature of (Subject + Display + HTML). If these three match exactly across accounts, they are considered the same creative and shown as a single aggregate row with Accounts listing.')
