# streamlit_email_html_extractor.py
# Requirements:
# pip install streamlit beautifulsoup4 lxml scikit-learn numpy pandas joblib

import streamlit as st
import imaplib
import email
import quopri
import base64
import re
import os
import tempfile
import shutil
import zipfile
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import AgglomerativeClustering
import uuid
from pathlib import Path
import time

st.set_page_config(page_title="Email HTML Extractor & Cluster Zipper", layout="wide")
st.title("Email HTML Extractor — decode, cluster, zip")

st.markdown(
    """
Provide an email (IMAP) account and app password. The app will pull HTML creatives from the selected mailbox/folder(s),
attempt to decode encoded parts (base64, quoted-printable), extract HTML + CSS, cluster similar templates into batches,
and produce a final ZIP containing subfolders for each cluster.

**Security:** your credentials are used only for the running session. For Gmail use an AppPassword or OAuth IMAP token — do not paste your regular password if 2FA is enabled.
"""
)

# -------------------------
# Sidebar connection / folder UI
# -------------------------
with st.sidebar.form("connection_form"):
    st.header("Connection & source folders")
    imap_host = st.text_input("IMAP host (e.g. imap.gmail.com)", value="imap.gmail.com")
    # Keep port hidden (default 993)
    imap_port = 993
    email_user = st.text_input("Email (username)")
    app_password = st.text_input("App password / IMAP password", type="password")

    # try to list folders if creds are present
    imap_folders = []
    if email_user and app_password and imap_host:
        try:
            tmp_conn = imaplib.IMAP4_SSL(imap_host, imap_port, timeout=20)
            tmp_conn.login(email_user, app_password)
            res, flist = tmp_conn.list()
            if res == 'OK' and flist:
                for entry in flist:
                    try:
                        s = entry.decode(errors='ignore').strip()
                        # typical formats: '(\HasNoChildren) "/" "INBOX"'  OR  '(\HasNoChildren) "/" INBOX'
                        m = re.search(r'"([^"]+)"$', s)
                        if m:
                            name = m.group(1)
                        else:
                            parts = s.split()
                            name = parts[-1].strip('"')
                        if name and name not in imap_folders:
                            imap_folders.append(name)
                    except Exception:
                        continue
            else:
                # show raw result for debugging (helps adapt to provider formats)
                st.text_area("IMAP list raw (debug)", value=str(flist), height=100)
            tmp_conn.logout()
        except Exception as e:
            st.warning("Folder listing failed. Check credentials or provider IMAP LIST support.")
            st.text_area("IMAP list error (debug)", value=str(e), height=120)
            imap_folders = []

    # fallback common folders if listing couldn't find anything
    if not imap_folders:
        imap_folders = ["INBOX", "Sent", "Drafts", "Trash", "Spam"]

    mail_folders = st.multiselect(
        "Select folders to include (choose one or many)",
        options=imap_folders,
        default=["INBOX"]
    )

    show_advanced = st.checkbox("Show advanced settings")

    if show_advanced:
        max_messages = st.number_input("Max messages to fetch (0 = all)", min_value=0, value=5000)
        workers = st.number_input("Parallel workers (instances)", min_value=1, max_value=32, value=1)
        cluster_mode = st.selectbox("Clustering mode", ["Fixed clusters (n)", "Distance threshold"], index=0)
        if cluster_mode == "Fixed clusters (n)":
            n_clusters = st.number_input("Number of clusters (n)", min_value=1, value=10)
            distance_threshold = None
        else:
            distance_threshold = st.number_input("Linkage distance threshold (smaller = more clusters)", min_value=0.0, value=1.5, step=0.1)
            n_clusters = None
    else:
        # simplified defaults (safe for <5k mailboxes)
        max_messages = 5000
        workers = 1
        cluster_mode = 'Fixed clusters (n)'
        n_clusters = 10
        distance_threshold = None

    search_query = st.text_input("IMAP search query (e.g. ALL, UNSEEN, SINCE 01-Jan-2024)", value="ALL")
    submit = st.form_submit_button("Start extraction & clustering")

# -------------------------
# Helpers
# -------------------------
CLEAN_RE_PATTERNS = [
    (re.compile(r"data:image/[^;]+;base64,[A-Za-z0-9+/=]+"), ""),
    (re.compile(r"https?://\S+"), ""),
    (re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+"), ""),
    (re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE), ""),
]


def decode_part(part):
    content = part.get_payload(decode=False)
    cte = part.get('Content-Transfer-Encoding', '').lower()
    try:
        if cte == 'base64':
            decoded = base64.b64decode(content)
        elif cte in ('quoted-printable', 'quopri'):
            decoded = quopri.decodestring(content)
        else:
            decoded = part.get_payload(decode=True)
            if decoded is None:
                decoded = content.encode('utf-8', errors='ignore') if isinstance(content, str) else content
    except Exception:
        decoded = content if isinstance(content, bytes) else str(content).encode('utf-8', errors='ignore')
    return decoded


def extract_html_and_css_from_message(msg_bytes):
    try:
        msg = email.message_from_bytes(msg_bytes)
    except Exception:
        return []

    results = []
    for part in msg.walk():
        ctype = part.get_content_type()
        try:
            payload = part.get_payload(decode=True) or b''
            payload_text = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore') if isinstance(payload, (bytes, bytearray)) else str(payload)
        except Exception:
            payload_text = ''

        if ctype == 'text/html' or (ctype == 'text/plain' and '<html' in payload_text.lower()):
            decoded = decode_part(part)
            if not decoded:
                continue
            try:
                html = decoded.decode(part.get_content_charset() or 'utf-8', errors='ignore') if isinstance(decoded, (bytes, bytearray)) else str(decoded)
            except Exception:
                html = decoded.decode('utf-8', errors='ignore') if isinstance(decoded, (bytes, bytearray)) else str(decoded)

            soup = BeautifulSoup(html, 'lxml')
            styles = ''.join([s.get_text() for s in soup.find_all('style')])
            for tag in soup.find_all(['script']):
                tag.decompose()
            for t in soup.find_all(True):
                if t.has_attr('src'):
                    del t['src']
                if t.has_attr('href'):
                    del t['href']
                if t.has_attr('id'):
                    del t['id']
                if t.has_attr('class'):
                    del t['class']

            cleaned_html = str(soup)
            results.append({'html': cleaned_html, 'css': styles})
    return results


def clean_for_vector(text):
    txt = text.lower()
    for pat, repl in CLEAN_RE_PATTERNS:
        txt = pat.sub(repl, txt)
    txt = re.sub(r'\s+', ' ', txt)
    return txt


def fetch_message_by_uid(imap_conn, uid):
    res, data = imap_conn.uid('fetch', uid, '(RFC822)')
    if res != 'OK':
        return None
    return data[0][1]


def process_uids_segment_sequential(uids, folders, imap_host, imap_port, user, pwd, progress_cb=None):
    """
    Sequential fetching across folders (used when workers=1 to enable per-message progress updates).
    progress_cb(uid, folder, index, total) is optional callback to report progress.
    """
    results = []
    imap = imaplib.IMAP4_SSL(imap_host, imap_port)
    imap.login(user, pwd)
    total = len(uids)
    counter = 0
    for uid in uids:
        counter += 1
        for f in folders:
            try:
                imap.select(f)
            except Exception:
                continue
            raw = fetch_message_by_uid(imap, uid)
            if not raw:
                continue
            parts = extract_html_and_css_from_message(raw)
            if parts:
                results.append({'uid': uid, 'folder': f, 'parts': parts})
        if progress_cb:
            progress_cb(uid, f if 'f' in locals() else 'unknown', counter, total)
    try:
        imap.logout()
    except Exception:
        pass
    return {'error': None, 'data': results}


def process_uids_segment_parallel(uids, folders, imap_host, imap_port, user, pwd):
    """
    Worker function used by ThreadPoolExecutor: each worker opens its own IMAP connection and processes its chunk.
    Returns {'error': str or None, 'data': [...]}
    """
    try:
        imap = imaplib.IMAP4_SSL(imap_host, imap_port)
        imap.login(user, pwd)
    except Exception as e:
        return {'error': str(e), 'data': []}

    results = []
    for uid in uids:
        for f in folders:
            try:
                imap.select(f)
            except Exception:
                continue
            raw = fetch_message_by_uid(imap, uid)
            if not raw:
                continue
            parts = extract_html_and_css_from_message(raw)
            if parts:
                results.append({'uid': uid, 'folder': f, 'parts': parts})
    try:
        imap.logout()
    except Exception:
        pass
    return {'error': None, 'data': results}


def chunkify(lst, n):
    if n <= 0:
        yield lst
    else:
        for i in range(0, len(lst), n):
            yield lst[i:i+n]


# -------------------------
# Main execution
# -------------------------
if submit:
    if not (email_user and app_password and imap_host and mail_folders):
        st.error("Provide IMAP host, email, app password and select at least one folder.")
    else:
        tmpdir = Path(tempfile.mkdtemp(prefix='email_html_extract_'))
        st.info(f"Working directory: {tmpdir}")
        main_progress = st.progress(0)
        status = st.empty()
        fetch_status = st.empty()   # for per-message status line

        try:
            # open a quick connection to collect UIDs across selected folders
            imap_root = imaplib.IMAP4_SSL(imap_host, imap_port)
            imap_root.login(email_user, app_password)

            all_uids = []
            for f in mail_folders:
                try:
                    imap_root.select(f)
                    res, data = imap_root.uid('search', None, search_query)
                    if res == 'OK':
                        uids = data[0].split()
                        all_uids.extend(uids)
                except Exception as e:
                    st.warning(f"Could not search folder {f}: {e}")
                    continue

            try:
                all_uids = sorted(all_uids, key=lambda x: int(x))
            except Exception:
                # leave order as returned if not numeric
                pass

            if max_messages and int(max_messages) > 0 and len(all_uids) > int(max_messages):
                # keep most recent messages
                all_uids = all_uids[-int(max_messages):]

            total = len(all_uids)
            if total == 0:
                st.info("No messages found for selected folders / query.")
            else:
                status.write(f"Found {total} messages across folders. Fetching with {workers} worker(s)...")

                extracted = []
                if workers == 1:
                    # sequential mode -> per-message progress updates
                    def progress_cb(uid, folder, idx, total_count):
                        pct = int((idx / float(total_count)) * 100)
                        main_progress.progress(pct)
                        fetch_status.markdown(f"Fetching UID: `{uid.decode() if isinstance(uid, bytes) else uid}`  — folder: `{folder}`  — {idx}/{total_count}")

                    # do sequential fetch so we can show fine-grained progress
                    resobj = process_uids_segment_sequential(all_uids, mail_folders, imap_host, imap_port, email_user, app_password, progress_cb=progress_cb)
                    if resobj.get('error'):
                        st.warning("Fetch error: " + resobj['error'])
                    extracted = resobj.get('data', [])
                    main_progress.progress(100)
                else:
                    # parallel mode: split into chunks, show chunk completion progress
                    chunk_size = max(1, int(len(all_uids) // workers))
                    chunks = list(chunkify(all_uids, chunk_size))
                    processed_chunks = 0
                    with ThreadPoolExecutor(max_workers=workers) as executor:
                        futures = [executor.submit(process_uids_segment_parallel, chunk, mail_folders, imap_host, imap_port, email_user, app_password) for chunk in chunks]
                        for fut in as_completed(futures):
                            resobj = fut.result()
                            if resobj.get('error'):
                                st.warning("Worker error: " + resobj['error'])
                            extracted.extend(resobj.get('data', []))
                            processed_chunks += 1
                            main_progress.progress(int(processed_chunks / max(1, len(chunks)) * 100))
                            fetch_status.write(f"Completed chunk {processed_chunks}/{len(chunks)}")
                    main_progress.progress(100)

                st.write(f"Extracted HTML parts from {len(extracted)} messages (messages that had HTML).")

                # flatten parts into files
                file_records = []
                for msg in extracted:
                    uid = msg['uid'].decode() if isinstance(msg['uid'], bytes) else str(msg['uid'])
                    folder = msg.get('folder', 'unknown')
                    for idx, part in enumerate(msg['parts']):
                        fid = f"{folder}_{uid}_{idx}_{uuid.uuid4().hex[:6]}"
                        html_name = tmpdir / f"{fid}.html"
                        css_name = tmpdir / f"{fid}.css"
                        html_text = part['html']
                        css_text = part['css'] or ''
                        html_name.write_text(html_text, encoding='utf-8')
                        css_name.write_text(css_text, encoding='utf-8')
                        file_records.append({'uid': uid, 'folder': folder, 'index': idx, 'html_path': str(html_name), 'css_path': str(css_name), 'html_text': html_text})

                st.write(f"Saved {len(file_records)} html parts to disk.")

                # clustering
                st.write("Preparing documents for similarity clustering...")
                docs = [clean_for_vector(r['html_text']) for r in file_records]
                if len(docs) == 0:
                    st.error('No HTML documents to cluster.')
                else:
                    vectorizer = TfidfVectorizer(max_features=20000, ngram_range=(1,3), stop_words='english')
                    X = vectorizer.fit_transform(docs)

                    if cluster_mode == 'Fixed clusters (n)':
                        ncl = min(int(n_clusters), len(docs))
                        model = AgglomerativeClustering(n_clusters=ncl, affinity='euclidean', linkage='ward')
                    else:
                        model = AgglomerativeClustering(n_clusters=None, distance_threshold=float(distance_threshold), affinity='euclidean', linkage='ward')

                    labels = model.fit_predict(X.toarray())

                    clusters = {}
                    for rec, lab in zip(file_records, labels):
                        clusters.setdefault(int(lab), []).append(rec)

                    out_zip_path = tmpdir / f"email_templates_clusters_{uuid.uuid4().hex[:8]}.zip"
                    with zipfile.ZipFile(out_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for lab, items in clusters.items():
                            folder_name = f"cluster_{lab}"
                            for it in items:
                                arc_html = str(Path(folder_name) / Path(it['html_path']).name)
                                zf.write(it['html_path'], arc_html)
                                if os.path.exists(it['css_path']) and Path(it['css_path']).stat().st_size > 0:
                                    arc_css = str(Path(folder_name) / Path(it['css_path']).name)
                                    zf.write(it['css_path'], arc_css)

                    st.success(f"Created ZIP with {len(clusters)} clusters: {out_zip_path}")
                    with open(out_zip_path, 'rb') as fh:
                        st.download_button(label='Download clustered ZIP', data=fh.read(), file_name=out_zip_path.name)

        except Exception as e:
            st.exception(e)
        finally:
            try:
                shutil.rmtree(tmpdir)
            except Exception:
                pass

st.markdown("---")
st.caption('Notes: This script is a practical starter. For mailboxes with tens of thousands of messages, run on a machine with sufficient memory and consider using a job queue / chunked persistence. Clustering quality will improve if you further normalize templates (remove timestamps, numbers, GUIDs) and tune vectorizer parameters.')
