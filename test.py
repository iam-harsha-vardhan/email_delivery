# app.py
# Inbox Creative Fetcher — Single Table + Preview column (full HTML in table + easy copy)
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
import html as html_module
import uuid
import hashlib
import streamlit.components.v1 as components
import json

st.set_page_config(page_title="Inbox Creative Fetcher — Single Table + Previews", layout="wide")
st.title("📥 Inbox Creative Fetcher — Table (Full HTML) + Previews")

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
    html_text = re.sub(r'(?is)<(script|style).*?>.*?</\1>', ' ', html_text)
    text = re.sub(r'<[^>]+>', ' ', html_text)
    text = html_module.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
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
        sentences = re.split(r'(?<=[\.\?!])\s+', stripped)
        display = ' '.join([s for s in sentences if s.strip()][:3]) or '-'

    if found_html:
        html_clean = re.sub(r'\s+', ' ', found_html).strip()
        return subject, display, html_clean
    else:
        return subject, display, '-'

def make_signature(subject, display, html_text):
    key = (subject or '') + '\n||\n' + (display or '') + '\n||\n' + (html_text or '')
    return hashlib.sha256(key.encode('utf-8')).hexdigest()

# ---------- Fast IMAP fetch (server-side search when possible) ----------
def fetch_last_n_for_account_fast(email_addr, password, domain_substring, max_messages=DEFAULT_MAX_MESSAGES, uid_scan_limit=UID_SCAN_LIMIT):
    rows = []
    try:
        imap = imaplib.IMAP4_SSL('imap.gmail.com')
        imap.login(email_addr.strip(), password.strip())
        imap.select('inbox')

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

        # fetch in batches
        for i in range(0, len(selected_uids), BATCH_FETCH_SIZE):
            chunk = selected_uids[i:i+BATCH_FETCH_SIZE]
            uid_seq = b','.join(chunk)
            try:
                res, md = imap.uid('fetch', uid_seq, '(BODY.PEEK[])')
            except Exception:
                # fallback per-UID
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
                # extract uid if present in meta
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

# ---------- UI ----------
st.markdown("### 🔎 Input — last N messages per account (fast search)")
st.info("Add one or more accounts (Email + App Password). Optionally provide a domain substring (server-side FROM search) to speed things up.")

if 'creds_df' not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{'Email':'','Password':''}])

edited = st.data_editor(st.session_state.creds_df, num_rows='dynamic', use_container_width=True, hide_index=True)
st.session_state.creds_df = edited

col1, col2 = st.columns([2,1])
with col1:
    domain_input = st.text_input('Domain substring to filter FROM header (optional)', value='')
with col2:
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

            # Aggregate by exact signature
            agg = {}
            for _, r in raw_df.iterrows():
                sig = make_signature(r['Subject'], r['Display'], r['HTML'])
                if sig not in agg:
                    agg[sig] = {
                        'Subject': r['Subject'],
                        'Display': r['Display'],
                        'HTML': r['HTML'],
                        'Accounts': set([r['Account']])
                    }
                else:
                    agg[sig]['Accounts'].add(r['Account'])

            # Build a stable ordered list for rendering
            entries = []
            for sig, v in agg.items():
                entries.append({
                    'signature': sig,
                    'subject': v['Subject'],
                    'display': v['Display'],
                    'html': (v['HTML'] if v['HTML'] and v['HTML'] != '-' else ''),
                    'accounts_count': len(v['Accounts']),
                    'accounts_list': ', '.join(sorted(v['Accounts']))
                })

            # Show a two-column layout: left = table, right = previews grid
            left_col, right_col = st.columns([2, 1])
            # Build HTML table for left column so we can put copy buttons beside each HTML cell
            table_rows_html = []
            for idx, e in enumerate(entries, start=1):
                # safe values for display in table (escape for innerText/JS string)
                disp_safe = html_module.escape(e['display'] or '-')
                subj_safe = html_module.escape(e['subject'] or '-')
                html_full = e['html'] or ''
                # JSON-encode html to safely embed in JS
                html_js = json.dumps(html_full)
                # put the full html into a <pre> for easier copy, with an id
                pre_id = f"html_cell_{idx}"
                copy_btn_id = f"copy_table_btn_{idx}"
                row_html = f"""
                <tr style="vertical-align:top; border-bottom:1px solid #ddd;">
                  <td style="padding:8px; max-width:260px; white-space:normal;">{disp_safe}</td>
                  <td style="padding:8px; max-width:360px; white-space:normal;">{subj_safe}</td>
                  <td style="padding:8px; max-width:560px;">
                    <div style="display:flex; gap:8px; align-items:flex-start;">
                      <button id="{copy_btn_id}">Copy</button>
                      <pre id="{pre_id}" style="max-height:140px; overflow:auto; white-space:pre-wrap; word-wrap:break-word; margin:0; padding:6px; border:1px solid #eee; background:#fafafa;">{html_module.escape(html_full)}</pre>
                    </div>
                    <script>
                      document.getElementById("{copy_btn_id}").onclick = function() {{
                        const txt = {html_js};
                        navigator.clipboard.writeText(txt).then(()=>{{ this.innerText='Copied'; setTimeout(()=>{{ this.innerText='Copy'; }},1200); }});
                      }};
                    </script>
                  </td>
                  <td style="padding:8px; text-align:center;">{e['accounts_count']}</td>
                </tr>
                """
                table_rows_html.append(row_html)

            full_table_html = f"""
            <div style="overflow:auto; border:1px solid #eee; padding:6px; border-radius:6px;">
              <table style="border-collapse:collapse; width:100%; font-family:Arial, sans-serif;">
                <thead>
                  <tr style="background:#f7f7f7; text-align:left;">
                    <th style="padding:10px; width:20%;">Display</th>
                    <th style="padding:10px; width:25%;">Subject</th>
                    <th style="padding:10px; width:45%;">HTML (full)</th>
                    <th style="padding:10px; width:10%;"># Accounts</th>
                  </tr>
                </thead>
                <tbody>
                  {''.join(table_rows_html)}
                </tbody>
              </table>
            </div>
            """

            with left_col:
                st.subheader("Single Table — Display | Subject | Full HTML | #Accounts")
                # Use components.html to render our custom table (so JS copy buttons work)
                # height scales with number of rows (approx)
                est_height = max(400, 120 + len(entries) * 80)
                components.html(full_table_html, height=est_height, scrolling=True)

            # Right column: preview boxes, each with copy at top
            with right_col:
                st.subheader("Previews")
                previews_html_parts = []
                for idx, e in enumerate(entries, start=1):
                    sig = e['signature'] if 'signature' in e else str(idx)
                    html_content = e['html'] or ''
                    html_js = json.dumps(html_content)
                    preview_id = f"preview_box_{idx}"
                    copy_id = f"copy_preview_btn_{idx}"
                    accounts_text = html_module.escape(e['accounts_list'])
                    small_box = f"""
                    <div style="border:1px solid #ddd; border-radius:6px; padding:8px; margin-bottom:12px; background:#fff;">
                      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <div style="font-size:12px; color:#444;"><strong>Accounts:</strong> {e['accounts_count']}</div>
                        <div>{'<button id="%s">Copy</button>'%copy_id}</div>
                      </div>
                      <div id="{preview_id}" style="border:1px solid #f0f0f0; padding:6px; min-height:60px; max-height:220px; overflow:auto; background:#fafafa;">
                        <!-- HTML will be injected here -->
                      </div>
                      <div style="font-size:11px; color:#666; margin-top:6px;">{accounts_text}</div>
                      <script>
                        (function() {{
                          const box = document.getElementById("{preview_id}");
                          const htmlSource = {html_js};
                          box.innerHTML = htmlSource || "<div style='color:#666;'>No HTML</div>";
                          const btn = document.getElementById("{copy_id}");
                          btn.onclick = function() {{
                            navigator.clipboard.writeText(htmlSource).then(()=>{{ btn.innerText='Copied'; setTimeout(()=>{{ btn.innerText='Copy'; }},1200); }});
                          }};
                        }})();
                      </script>
                    </div>
                    """
                    previews_html_parts.append(small_box)

                previews_wrapper = "<div style='max-height:800px; overflow:auto;'>" + "".join(previews_html_parts) + "</div>"
                components.html(previews_wrapper, height=800, scrolling=True)

            st.success("Table + previews rendered. Use Copy buttons in table or in preview boxes to copy full HTML.")

st.markdown('---')
st.caption('Notes: The table shows the full HTML inside a scrollable <pre> with a copy button. The right column previews every creative and has a copy button at the top of each preview box. If your HTML contains scripts that should not run in the preview, be cautious — previews directly inject the HTML into the page (expected for email templates which are typically HTML/CSS only).')
