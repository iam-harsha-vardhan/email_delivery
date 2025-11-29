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
import time
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import AgglomerativeClustering
import uuid
from pathlib import Path

st.set_page_config(page_title="Email HTML Extractor (batched)", layout="wide")
st.title("Email HTML Extractor — batched fetch, decode, cluster, zip")

st.markdown("""
This app will fetch emails *in batches* (default 500 per batch) to avoid overloading IMAP servers,
decode HTML parts, then cluster all extracted templates and produce a ZIP with subfolders per cluster.

For Gmail use an App Password or OAuth token (do not paste your regular password if 2FA is enabled).
""")

# -------------------------
# Sidebar / connection UI
# -------------------------
with st.sidebar.form("conn"):
    st.header("Connection & options")
    imap_host = st.text_input("IMAP host", value="imap.gmail.com")
    email_user = st.text_input("Email (username)")
    app_password = st.text_input("App password / IMAP password", type="password")

    # folder fetch listing attempt (quiet)
    imap_folders = []
    if email_user and app_password and imap_host:
        try:
            tmp = imaplib.IMAP4_SSL(imap_host, 993, timeout=20)
            tmp.login(email_user, app_password)
            res, flist = tmp.list()
            if res == 'OK' and flist:
                for e in flist:
                    try:
                        s = e.decode(errors='ignore').strip()
                        m = re.search(r'"([^"]+)"$', s)
                        if m:
                            name = m.group(1)
                        else:
                            parts = s.split()
                            name = parts[-1].strip('"')
                        if name not in imap_folders:
                            imap_folders.append(name)
                    except Exception:
                        continue
            tmp.logout()
        except Exception:
            # silently ignore; fallback below
            imap_folders = []

    if not imap_folders:
        imap_folders = ["INBOX", "Sent", "Drafts", "Trash", "Spam"]

    mail_folders = st.multiselect("Folders to include", options=imap_folders, default=["INBOX"])

    # batching / parallelism
    batch_size = st.number_input("Batch size (messages per batch)", min_value=50, max_value=5000, value=500, step=50)
    workers = st.number_input("Workers per batch (parallel fetch within batch)", min_value=1, max_value=16, value=1)
    max_messages = st.number_input("Max total messages to fetch (0 = all)", min_value=0, value=0)

    # clustering options
    cluster_mode = st.selectbox("Clustering mode", ["Fixed clusters (n)", "Distance threshold"])
    if cluster_mode == "Fixed clusters (n)":
        n_clusters = st.number_input("Number of clusters (n)", min_value=1, value=10)
        distance_threshold = None
    else:
        distance_threshold = st.number_input("Linkage distance threshold", min_value=0.0, value=1.5, step=0.1)
        n_clusters = None

    # login retry/backoff
    max_retries = st.number_input("Login max retries (per worker)", min_value=0, max_value=10, value=3)
    base_retry_delay = st.number_input("Base retry delay (sec)", min_value=1, max_value=60, value=5)

    submit = st.form_submit_button("Start")

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
    cte = (part.get('Content-Transfer-Encoding') or '').lower()
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
            for t in soup.find_all(['script']): t.decompose()
            for t in soup.find_all(True):
                if t.has_attr('src'): del t['src']
                if t.has_attr('href'): del t['href']
                if t.has_attr('id'): del t['id']
                if t.has_attr('class'): del t['class']
            cleaned_html = str(soup)
            results.append({'html': cleaned_html, 'css': styles})
    return results

def clean_for_vector(text):
    txt = text.lower()
    for pat, repl in CLEAN_RE_PATTERNS:
        txt = pat.sub(repl, txt)
    txt = re.sub(r'\s+', ' ', txt)
    return txt

def fetch_message_by_uid_with_retry(imap_conn, uid):
    # returns raw bytes or None
    try:
        res, data = imap_conn.uid('fetch', uid, '(RFC822)')
        if res != 'OK': 
            return None
        return data[0][1]
    except Exception:
        return None

def worker_fetch_chunk_chunked(uids_chunk, folders, imap_host, imap_port, user, pwd, retry_opts):
    """Worker used when workers>1 inside a batch. It performs its own login with retries then fetches assigned uids across folders."""
    max_retries, base_delay = retry_opts
    attempt = 0
    backoff = base_delay
    while True:
        try:
            conn = imaplib.IMAP4_SSL(imap_host, imap_port)
            conn.login(user, pwd)
            break
        except Exception as e:
            attempt += 1
            if attempt > max_retries:
                return {'error': f'login failed after {max_retries} attempts: {e}', 'data': []}
            time.sleep(backoff)
            backoff *= 2
    out = []
    try:
        for uid in uids_chunk:
            for f in folders:
                try:
                    conn.select(f)
                except Exception:
                    continue
                raw = fetch_message_by_uid_with_retry(conn, uid)
                if not raw: 
                    continue
                parts = extract_html_and_css_from_message(raw)
                if parts:
                    out.append({'uid': uid, 'folder': f, 'parts': parts})
    finally:
        try:
            conn.logout()
        except Exception:
            pass
    return {'error': None, 'data': out}

def sequential_fetch_batch(uids_batch, folders, imap_host, imap_port, user, pwd, progress_cb=None, retry_opts=(3,5)):
    """Sequentially fetch the batch (single connection) and call progress_cb(uid, idx, total) as progress updates."""
    max_retries, base_delay = retry_opts
    attempt = 0
    backoff = base_delay
    while True:
        try:
            conn = imaplib.IMAP4_SSL(imap_host, imap_port)
            conn.login(user, pwd)
            break
        except Exception as e:
            attempt += 1
            if attempt > max_retries:
                return {'error': f'login failed after {max_retries} attempts: {e}', 'data': []}
            time.sleep(backoff)
            backoff *= 2
    out = []
    total = len(uids_batch)
    for i, uid in enumerate(uids_batch, start=1):
        for f in folders:
            try:
                conn.select(f)
            except Exception:
                continue
            raw = fetch_message_by_uid_with_retry(conn, uid)
            if raw:
                parts = extract_html_and_css_from_message(raw)
                if parts:
                    out.append({'uid': uid, 'folder': f, 'parts': parts})
        if progress_cb:
            progress_cb(uid, i, total)
    try:
        conn.logout()
    except Exception:
        pass
    return {'error': None, 'data': out}

def chunkify_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

# -------------------------
# Run when user clicks Start
# -------------------------
if submit:
    if not (imap_host and email_user and app_password and mail_folders):
        st.error("Provide IMAP host, email, password and select at least one folder.")
    else:
        tmpdir = Path(tempfile.mkdtemp(prefix='email_html_extract_'))
        st.info(f"Working dir: {tmpdir}")
        batch_progress = st.progress(0)
        message_status = st.empty()
        overall_status = st.empty()

        # collect UIDs across selected folders using one connection (light)
        try:
            root_conn = imaplib.IMAP4_SSL(imap_host, 993)
            root_conn.login(email_user, app_password)
        except Exception as e:
            st.error(f"Initial login failed: {e}")
            raise SystemExit

        all_uids = []
        for f in mail_folders:
            try:
                root_conn.select(f)
                res, data = root_conn.uid('search', None, 'ALL')
                if res == 'OK':
                    uids = data[0].split()
                    all_uids.extend(uids)
            except Exception as e:
                st.warning(f"Could not search folder {f}: {e}")
        try:
            root_conn.logout()
        except Exception:
            pass

        # sort numeric if possible
        try:
            all_uids = sorted(all_uids, key=lambda x: int(x))
        except Exception:
            pass

        if max_messages and int(max_messages) > 0 and len(all_uids) > int(max_messages):
            all_uids = all_uids[-int(max_messages):]

        total_messages = len(all_uids)
        if total_messages == 0:
            st.info("No messages found for selected folders/query.")
        else:
            overall_status.write(f"Found {total_messages} messages. Fetching in batches of {batch_size}...")

            # split UIDs into batches
            batches = list(chunkify_list(all_uids, batch_size))
            n_batches = len(batches)
            all_extracted = []  # collect all extracted items across batches

            for bi, batch in enumerate(batches, start=1):
                batch_status = f"Batch {bi}/{n_batches} ({len(batch)} messages)"
                overall_status.write(batch_status)
                message_progress = st.progress(0)
                message_line = st.empty()

                # if workers==1 do sequential_fetch_batch to show per-message progress
                if workers == 1:
                    def progress_cb(uid, idx, total):
                        pct = int((idx/total)*100)
                        message_progress.progress(pct)
                        message_line.markdown(f"Fetching UID `{uid.decode() if isinstance(uid, bytes) else uid}` — {idx}/{total}")

                    resobj = sequential_fetch_batch(batch, mail_folders, imap_host, 993, email_user, app_password, progress_cb=progress_cb, retry_opts=(int(max_retries), int(base_retry_delay)))
                    if resobj.get('error'):
                        st.warning(f"Batch {bi} error: {resobj['error']}")
                    else:
                        all_extracted.extend(resobj.get('data', []))
                    message_progress.progress(100)
                else:
                    # parallel inside batch: split UIDs among workers and submit worker_fetch_chunk_chunked
                    chunk_size_in_batch = max(1, int(len(batch) // workers))
                    subchunks = list(chunkify_list(batch, chunk_size_in_batch))
                    with ThreadPoolExecutor(max_workers=workers) as ex:
                        futures = [ex.submit(worker_fetch_chunk_chunked, sc, mail_folders, imap_host, 993, email_user, app_password, (int(max_retries), int(base_retry_delay))) for sc in subchunks]
                        completed = 0
                        for fut in as_completed(futures):
                            resobj = fut.result()
                            if resobj.get('error'):
                                st.warning(f"Worker error in batch {bi}: {resobj['error']}")
                            else:
                                all_extracted.extend(resobj.get('data', []))
                            completed += 1
                            message_progress.progress(int(completed/len(subchunks)*100))
                            message_line.write(f"Completed {completed}/{len(subchunks)} parallel workers for this batch")
                    message_progress.progress(100)

                # free batch UI elements
                message_line.empty()
                message_progress.empty()
                # update batch-level progress
                batch_progress.progress(int(bi / n_batches * 100))

            # all batches fetched; now flatten and cluster
            st.write(f"Fetched all batches. Total extracted messages with HTML parts: {len(all_extracted)}")

            # flatten parts into files
            file_records = []
            for item in all_extracted:
                uid = item['uid'].decode() if isinstance(item['uid'], bytes) else str(item['uid'])
                folder = item.get('folder', 'unknown')
                for idx, part in enumerate(item['parts']):
                    fid = f"{folder}_{uid}_{idx}_{uuid.uuid4().hex[:6]}"
                    html_path = tmpdir / f"{fid}.html"
                    css_path = tmpdir / f"{fid}.css"
                    html_path.write_text(part['html'], encoding='utf-8')
                    css_path.write_text(part.get('css', ''), encoding='utf-8')
                    file_records.append({'uid': uid, 'folder': folder, 'html_path': str(html_path), 'css_path': str(css_path), 'html_text': part['html']})

            st.write(f"Saved {len(file_records)} html parts to disk in {tmpdir}.")

            # clustering
            st.write("Clustering templates...")
            docs = [clean_for_vector(r['html_text']) for r in file_records]
            if len(docs) == 0:
                st.error("No HTML docs to cluster.")
            else:
                vectorizer = TfidfVectorizer(max_features=20000, ngram_range=(1,3), stop_words='english')
                X = vectorizer.fit_transform(docs)
                if cluster_mode == "Fixed clusters (n)":
                    ncl = min(int(n_clusters), len(docs))
                    model = AgglomerativeClustering(n_clusters=ncl, affinity='euclidean', linkage='ward')
                else:
                    model = AgglomerativeClustering(n_clusters=None, distance_threshold=float(distance_threshold), affinity='euclidean', linkage='ward')

                labels = model.fit_predict(X.toarray())

                clusters = {}
                for rec, lab in zip(file_records, labels):
                    clusters.setdefault(int(lab), []).append(rec)

                out_zip = tmpdir / f"email_templates_clusters_{uuid.uuid4().hex[:8]}.zip"
                with zipfile.ZipFile(out_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for lab, items in clusters.items():
                        folder_name = f"cluster_{lab}"
                        for it in items:
                            arc_html = str(Path(folder_name) / Path(it['html_path']).name)
                            zf.write(it['html_path'], arc_html)
                            if os.path.exists(it['css_path']) and Path(it['css_path']).stat().st_size > 0:
                                arc_css = str(Path(folder_name) / Path(it['css_path']).name)
                                zf.write(it['css_path'], arc_css)

                st.success(f"Created ZIP with {len(clusters)} clusters: {out_zip.name}")
                with open(out_zip, 'rb') as fh:
                    st.download_button("Download clustered ZIP", fh.read(), file_name=out_zip.name)

        # cleanup: optional - keep for debugging, remove to free files
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

st.markdown("---")
st.caption("This version fetches in safe batches then clusters once fetching is complete.")
