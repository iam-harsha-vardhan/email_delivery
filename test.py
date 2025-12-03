# app.py
# Inbox Creative Fetcher — Sub-ID boxes with Preview + From + Subject + Copy
# Run: streamlit run app.py
# Requires: streamlit, pandas, pytz

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
import base64
import json

st.set_page_config(page_title="Inbox Creative Fetcher — SubID Previews", layout="wide")
st.title("📥 Inbox Creative Fetcher — Sub-ID Boxes + Previews")

# ---------- Config ----------
UID_SCAN_LIMIT = 2000
DEFAULT_MAX_MESSAGES = 20
BATCH_FETCH_SIZE = 100

# ---------- Sub-ID helpers ----------
ID_RE = re.compile(r'\b(GRM-[A-Za-z0-9\-]+|GMFP-[A-Za-z0-9\-]+|GTC-[A-Za-z0-9\-]+|GRTC-[A-Za-z0-9\-]+)\b', re.I)

def map_id_to_type(sub_id):
    if not sub_id: return "-"
    lid = sub_id.lower()
    if lid.startswith('grm'): return 'FPR'
    if lid.startswith('gmfp'): return 'FP'
    if lid.startswith('gtc'): return 'FPTC'
    if lid.startswith('grtc'): return 'FPRTC'
    return "-"

def try_base64_variants(s):
    if not s or len(s) < 4: return None
    s = s.strip()
    if s.startswith('<') and s.endswith('>'): s = s[1:-1]
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        for pad in range(0,4):
            try:
                cand = s + ('=' * pad)
                decoded = decoder(cand)
                try:
                    text = decoded.decode('utf-8', errors='ignore')
                except Exception:
                    continue
                if text and text.strip():
                    return text
            except Exception:
                continue
    return None

def find_subid_in_text(txt):
    if not txt: return None
    m = ID_RE.search(txt)
    return m.group(1) if m else None

def format_date_to_ist_string(raw_date):
    if not raw_date: return "-", None
    try:
        dt = parsedate_to_datetime(raw_date)
    except Exception:
        return raw_date, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    ist = pytz.timezone("Asia/Kolkata")
    dt_ist = dt.astimezone(ist)
    dt_ist_naive = dt_ist.replace(tzinfo=None)
    formatted = dt_ist.strftime("%d-%b-%Y %I:%M %p")
    return formatted, dt_ist_naive

def extract_subid_from_msg(msg):
    # message-id
    msg_id_raw = decode_mime_words(msg.get("Message-ID", "") or msg.get("Message-Id", "") or "")
    if msg_id_raw:
        tokens = re.split(r'[_\s]+', msg_id_raw)
        for t in tokens:
            maybe = find_subid_in_text(t)
            if maybe: return maybe, map_id_to_type(maybe)
            decoded = try_base64_variants(t)
            if decoded:
                m2 = find_subid_in_text(decoded)
                if m2: return m2, map_id_to_type(m2)
    headers_str = " ".join(f"{h}:{v}" for h,v in msg.items())
    maybe = find_subid_in_text(headers_str)
    if maybe: return maybe, map_id_to_type(maybe)
    try:
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain","text/html"):
                payload = part.get_payload(decode=True)
                if not payload: continue
                try:
                    text = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
                except Exception:
                    text = str(payload)
                maybe = find_subid_in_text(text)
                if maybe: return maybe, map_id_to_type(maybe)
                tokens = re.split(r'[^A-Za-z0-9_\-+/=]', text)
                for t in tokens:
                    if len(t) < 12: continue
                    dec = try_base64_variants(t)
                    if dec:
                        m2 = find_subid_in_text(dec)
                        if m2: return m2, map_id_to_type(m2)
    except Exception:
        pass
    return None, "-"

# ---------- MIME / HTML extraction helpers ----------
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

# ---------- IMAP fast fetch (server-side FROM search when provided) ----------
def fetch_last_n_for_account_fast(email_addr, password, domain_substring, max_messages=DEFAULT_MAX_MESSAGES, uid_scan_limit=UID_SCAN_LIMIT):
    rows = []
    try:
        imap = imaplib.IMAP4_SSL('imap.gmail.com')
        imap.login(email_addr.strip(), password.strip())
        imap.select('inbox')

        # do a targeted server-side search if domain_substring provided
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
                        # extract header 'From' from the header fetch if available
                        subject, display, html_creative = extract_subject_display_html_from_msg(msg)
                        # attempt to read 'From' header from msg (if not present, fallback to '-')
                        from_h = decode_mime_words(msg.get('From','-'))
                        sub_id, sid_type = extract_subid_from_msg(msg)
                        raw_date = msg.get('Date','')
                        formatted_date, dt = format_date_to_ist_string(raw_date)
                        rows.append({
                            'Account': email_addr,
                            'UID': u_str,
                            'From': from_h,
                            'Subject': subject,
                            'Display': display,
                            'HTML': html_creative,
                            'Date': formatted_date,
                            'Date_dt': dt,
                            'Sub ID': sub_id or "-",
                            'Type': sid_type
                        })
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
                # try to get UID from meta
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
                from_h = decode_mime_words(msg.get('From','-'))
                sub_id, sid_type = extract_subid_from_msg(msg)
                raw_date = msg.get('Date','')
                formatted_date, dt = format_date_to_ist_string(raw_date)
                rows.append({
                    'Account': email_addr,
                    'UID': uid_val,
                    'From': from_h,
                    'Subject': subject,
                    'Display': display,
                    'HTML': html_creative,
                    'Date': formatted_date,
                    'Date_dt': dt,
                    'Sub ID': sub_id or "-",
                    'Type': sid_type
                })

        imap.logout()
    except imaplib.IMAP4.error as e:
        st.error(f'IMAP error for {email_addr}: {e}')
        return rows
    except Exception as e:
        st.error(f'Error fetching {email_addr}: {e}')
        return rows

    return rows

# ---------- Preview box generator ----------
def preview_box_html_and_copy(html_content, copy_btn_id):
    # We will render the HTML literally inside the preview container, and provide a copy button that writes the exact HTML to clipboard.
    html_js = json.dumps(html_content or "")
    safe_preview = html_module.escape(html_content or "")
    return f"""
    <div style='border:1px solid #e6e6e6; border-radius:8px; padding:8px; background:#fff;'>
      <div style='display:flex; justify-content:flex-end; margin-bottom:6px;'>
        <button id='{copy_btn_id}' style='padding:6px 8px;'>Copy HTML</button>
      </div>
      <div style='min-height:60px; max-height:240px; overflow:auto; border:1px solid #f2f2f2; padding:6px; background:#fbfbfb;'>
        {safe_preview}
      </div>
      <script>
        (function(){{
          const btn = document.getElementById('{copy_btn_id}');
          const htmlSource = {html_js};
          btn.onclick = function(){{ navigator.clipboard.writeText(htmlSource).then(()=>{{ btn.innerText='Copied'; setTimeout(()=>{{ btn.innerText='Copy HTML'; }},1200); }}); }};
        }})();
      </script>
    </div>
    """

# ---------- UI ----------
st.markdown("### 🔎 Input — Fetch last N messages per account")
st.info("Add accounts (Email + App Password). Optionally provide a domain substring to let IMAP server filter messages (faster).")

if 'creds_df' not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{'Email':'','Password':''}])

edited = st.data_editor(st.session_state.creds_df, num_rows='dynamic', use_container_width=True, hide_index=True)
st.session_state.creds_df = edited

col1, col2 = st.columns([2,1])
with col1:
    domain_input = st.text_input('Domain substring to filter FROM header (optional)', value='')
with col2:
    max_msgs = st.number_input('Max messages per account', min_value=1, max_value=2000, value=DEFAULT_MAX_MESSAGES, step=1)

if st.button('Fetch across accounts'):
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
            st.info(f'Fetching for {acct}...')
            rows = fetch_last_n_for_account_fast(acct, pwd, domain_input.strip(), max_messages=max_msgs)
            all_rows.extend(rows)
            progress.progress(int(((i+1)/total)*100))

        if not all_rows:
            st.info('No messages found for provided accounts / domain.')
        else:
            df = pd.DataFrame(all_rows)

            # ---------- SUB-ID BOXES (no threshold) ----------
            st.subheader("🔎 Sub-IDs (every match shown)")
            # Build asset map keyed by Sub-ID (we want one box per Sub-ID)
            subid_map = {}  # subid -> {"accounts":set(),"examples":[rows], "htmls": set(), "latest_date":...}
            for _, row in df.iterrows():
                sid = row.get('Sub ID') or "-"
                if sid == "-" or sid is None:
                    continue
                entry = subid_map.setdefault(sid, {"accounts": set(), "examples": [], "htmls": set(), "latest_dt": None})
                entry["accounts"].add(row['Account'])
                entry["examples"].append(row)
                if row.get('HTML'):
                    entry["htmls"].add(row.get('HTML'))
                dt = row.get('Date_dt')
                if dt is not None and (entry["latest_dt"] is None or dt > entry["latest_dt"]):
                    entry["latest_dt"] = dt

            if not subid_map:
                st.info("No Sub-IDs found in the fetched messages.")
            else:
                # render boxes: grid of 2 columns
                sub_entries = []
                # sort subids by latest_dt desc (newest first)
                for sid, v in sorted(subid_map.items(), key=lambda x: (x[1]['latest_dt'] is None, x[1]['latest_dt']), reverse=True):
                    # choose representative Subject/From/Display from examples (use newest example)
                    ex = sorted(v['examples'], key=lambda r: (r.get('Date_dt') is None, r.get('Date_dt')), reverse=True)[0]
                    # If multiple HTMLs exist for same Sub-ID, concatenate with separator so copy gets all variants
                    html_joined = "\n\n<!-- === HTML variant separator === -->\n\n".join(list(v['htmls'])) if v['htmls'] else (ex.get('HTML') or '')
                    sub_entries.append({
                        'subid': sid,
                        'type': ex.get('Type', '-'),
                        'from': ex.get('From','-'),
                        'subject': ex.get('Subject','-'),
                        'display': ex.get('Display','-'),
                        'accounts_count': len(v['accounts']),
                        'accounts_list': ', '.join(sorted(v['accounts'])),
                        'html': html_joined
                    })

                cols_per_row = 2
                for row_start in range(0, len(sub_entries), cols_per_row):
                    cols = st.columns(cols_per_row)
                    for j in range(cols_per_row):
                        idx = row_start + j
                        if idx >= len(sub_entries):
                            continue
                        e = sub_entries[idx]
                        copy_btn_id = f"sub_copy_{idx}_{uuid.uuid4().hex[:6]}"
                        # Build preview box with copy and HTML render
                        box_html = preview_box_html_and_copy(e['html'], copy_btn_id)
                        with cols[j]:
                            st.markdown(f"**Sub-ID:** {e['subid']} — **Type:** {e['type']}")
                            components.html(box_html, height=260, scrolling=True)
                            st.markdown(f"**From:** {html_module.escape(e['from'])}  \n**Subject:** {html_module.escape(e['subject'])}  \n**Display:** {html_module.escape(e['display'])}")
                            st.markdown(f"**Accounts ({e['accounts_count']}):** {html_module.escape(e['accounts_list'])}")
                            st.markdown('---')

            st.success("Done — Sub-ID boxes rendered. Use Copy HTML in each box to copy the full HTML (all variants concatenated if multiple).")

st.markdown('---')
st.caption('Notes: Sub-IDs are extracted from Message-ID, headers and body (including trying base64 variations). Each Sub-ID box shows a preview and a Copy HTML button; the copy copies all HTML variants found for that Sub-ID (joined with a separator).')
