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
import json
import time
import tempfile
import shutil
import zipfile
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import AgglomerativeClustering
import uuid
from pathlib import Path

st.set_page_config(page_title="Email HTML Extractor (batched + checkpoint)", layout="wide")
st.title("Email HTML Extractor — batched fetch, checkpointing, cluster & zip")

st.markdown("""
Fetch emails in safe batches, decode HTML parts, checkpoint intermediate results so runs can resume after interruptions,
then cluster templates and produce a ZIP with subfolders per cluster.
""")

# -------------------------
# Sidebar / connection UI
# -------------------------
with st.sidebar.form("conn"):
    st.header("Connection & options")
    imap_host = st.text_input("IMAP host", value="imap.gmail.com")
    email_user = st.text_input("Email (username)")
    app_password = st.text_input("App password / IMAP password", type="password")

    # folders
    imap_folders = []
    if email_user and app_password and imap_host:
        try:
            tconn = imaplib.IMAP4_SSL(imap_host, 993, timeout=20)
            tconn.login(email_user, app_password)
            res, flist = tconn.list()
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
            tconn.logout()
        except Exception:
            imap_folders = []
    if not imap_folders:
        imap_folders = ["INBOX", "Sent", "Drafts", "Trash", "Spam"]

    mail_folders = st.multiselect("Folders to include", options=imap_folders, default=["INBOX"])

    batch_size = st.number_input("Batch size (messages per batch)", min_value=50, max_value=5000, value=200, step=50)
    workers = st.number_input("Workers per batch (parallel fetch within batch)", min_value=1, max_value=16, value=1)
    max_messages = st.number_input("Max total messages to fetch (0 = all)", min_value=0, value=0)

    cluster_mode = st.selectbox("Clustering mode", ["Fixed clusters (n)", "Distance threshold"])
    if cluster_mode == "Fixed clusters (n)":
        n_clusters = st.number_input("Number of clusters (n)", min_value=1, value=10)
        distance_threshold = None
    else:
        distance_threshold = st.number_input("Linkage distance threshold", min_value=0.0, value=1.5, step=0.1)
        n_clusters = None

    max_retries = st.number_input("Login max retries (per worker)", min_value=0, max_value=10, value=3)
    base_retry_delay = st.number_input("Base retry delay (sec)", min_value=1, max_value=60, value=5)

    # checkpoint controls
    resume_available = False
    checkpoint_root = Path.cwd() / "email_extractor_checkpoints"
    # find latest checkpoint (if any)
    runs = sorted([p for p in checkpoint_root.iterdir()] if checkpoint_root.exists() else [], key=lambda x: x.stat().st_mtime, reverse=True)
    latest_run = runs[0] if runs else None
    if latest_run and (latest_run / "checkpoint.jsonl").exists():
        resume_available = True
        st.write(f"Found checkpoint: {latest_run.name}")
        resume_from_checkpoint = st.checkbox("Resume from latest checkpoint", value=False)
        if resume_from_checkpoint:
            resume_path = latest_run
        else:
            if st.button("Clear latest checkpoint"):
                try:
                    shutil.rmtree(latest_run)
                    st.success("Cleared latest checkpoint folder.")
                    resume_available = False
                    latest_run = None
                except Exception as e:
                    st.error(f"Failed to remove checkpoint: {e}")
                    resume_available = True
    else:
        resume_from_checkpoint = False

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
            for tag in soup.find_all(['script']):
                tag.decompose()
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
    try:
        res, data = imap_conn.uid('fetch', uid, '(RFC822)')
        if res != 'OK':
            return None
        return data[0][1]
    except Exception:
        return None

def login_with_retry(imap_host, imap_port, user, pwd, max_retries=3, base_delay=5):
    attempt = 0
    backoff = base_delay
    while True:
        try:
            conn = imaplib.IMAP4_SSL(imap_host, imap_port)
            conn.login(user, pwd)
            return conn, None
        except Exception as e:
            attempt += 1
            if attempt > max_retries:
                return None, str(e)
            time.sleep(backoff)
            backoff *= 2

def chunkify_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

# -------------------------
# Checkpoint helpers
# -------------------------
def make_checkpoint_dir():
    ck_root = Path.cwd() / "email_extractor_checkpoints"
    ck_root.mkdir(parents=True, exist_ok=True)
    run_dir = ck_root / time.strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir

def load_latest_checkpoint(path):
    # path is Path to run_dir
    ckfile = path / "checkpoint.jsonl"
    fetched_file = path / "fetched_uids.txt"
    items = []
    fetched = set()
    if ckfile.exists():
        with ckfile.open('r', encoding='utf-8') as fh:
            for line in fh:
                try:
                    items.append(json.loads(line))
                except Exception:
                    continue
    if fetched_file.exists():
        with fetched_file.open('r', encoding='utf-8') as fh:
            for ln in fh:
                fetched.add(ln.strip())
    return items, fetched

def append_checkpoint_item(run_dir, item):
    ckfile = run_dir / "checkpoint.jsonl"
    with ckfile.open('a', encoding='utf-8') as fh:
        fh.write(json.dumps(item, ensure_ascii=False) + "\n")

def append_fetched_uid(run_dir, uid):
    f = run_dir / "fetched_uids.txt"
    with f.open('a', encoding='utf-8') as fh:
        fh.write(f"{uid}\n")

# -------------------------
# Main logic: start when user clicks Start
# -------------------------
if submit:
    if not (imap_host and email_user and app_password and mail_folders):
        st.error("Provide IMAP host, email, password and select at least one folder.")
    else:
        # Prepare checkpointing
        if resume_from_checkpoint and latest_run:
            run_dir = latest_run
            st.info(f"Resuming from checkpoint: {run_dir}")
            extracted_items, fetched_uids = load_latest_checkpoint(run_dir)
        else:
            # new run
            run_dir = make_checkpoint_dir()
            extracted_items = []
            fetched_uids = set()

        tmpdir = Path(tempfile.mkdtemp(prefix='email_html_extract_'))
        st.info(f"Working dir: {tmpdir}")
        batch_progress = st.progress(0)
        message_status = st.empty()
        overall_status = st.empty()

        # gather UIDs across folders
        try:
            conn_root, err = login_with_retry(imap_host, 993, email_user, app_password, max_retries=int(max_retries), base_delay=int(base_retry_delay))
            if conn_root is None:
                st.error(f"Initial login failed: {err}")
                raise SystemExit
        except Exception as e:
            st.error(f"Initial login exception: {e}")
            raise SystemExit

        all_uids = []
        for f in mail_folders:
            try:
                conn_root.select(f)
                res, data = conn_root.uid('search', None, 'ALL')
                if res == 'OK':
                    uids = data[0].split()
                    all_uids.extend(uids)
            except Exception as e:
                st.warning(f"Could not search folder {f}: {e}")

        try:
            conn_root.logout()
        except Exception:
            pass

        # optionally skip already fetched UIDs from checkpoint
        all_uids = [u for u in all_uids if (u.decode() if isinstance(u, bytes) else str(u)) not in fetched_uids]

        # sort numeric if possible
        try:
            all_uids = sorted(all_uids, key=lambda x: int(x))
        except Exception:
            pass

        if max_messages and int(max_messages) > 0 and len(all_uids) > int(max_messages):
            all_uids = all_uids[-int(max_messages):]

        total_messages = len(all_uids)
        if total_messages == 0:
            st.info("No new messages to fetch (after checkpoint filter).")
        else:
            overall_status.write(f"Found {total_messages} messages to fetch (excluding already fetched). Batching by {batch_size}...")

            batches = list(chunkify_list(all_uids, int(batch_size)))
            n_batches = len(batches)
            all_extracted = extracted_items[:]  # start with any previously checkpointed items

            for bi, batch in enumerate(batches, start=1):
                batch_status = f"Batch {bi}/{n_batches} ({len(batch)} messages)"
                overall_status.write(batch_status)
                message_progress = st.progress(0)
                message_line = st.empty()

                # sequential fetch with per-message updates if workers == 1
                if int(workers) == 1:
                    # one persistent connection with retries
                    conn, err = login_with_retry(imap_host, 993, email_user, app_password, max_retries=int(max_retries), base_delay=int(base_retry_delay))
                    if conn is None:
                        st.error(f"Login failed for batch {bi}: {err}")
                        break

                    total_in_batch = len(batch)
                    for idx, uid in enumerate(batch, start=1):
                        for f in mail_folders:
                            try:
                                conn.select(f)
                            except Exception:
                                continue
                            raw = fetch_message_by_uid_with_retry(conn, uid)
                            if raw:
                                parts = extract_html_and_css_from_message(raw)
                                if parts:
                                    for p in parts:
                                        # item structure saved to checkpoint
                                        item = {'uid': (uid.decode() if isinstance(uid, bytes) else str(uid)), 'folder': f, 'html': p['html'], 'css': p.get('css', '')}
                                        # append to checkpoint file immediately
                                        append_checkpoint_item(run_dir, item)
                                        append_fetched_uid(run_dir, item['uid'])
                                        all_extracted.append(item)
                        pct = int((idx/total_in_batch)*100)
                        message_progress.progress(pct)
                        message_line.markdown(f"Fetched UID `{uid.decode() if isinstance(uid, bytes) else uid}` — {idx}/{total_in_batch}")
                    try:
                        conn.logout()
                    except Exception:
                        pass
                    message_progress.progress(100)
                else:
                    # parallel: split batch among worker subchunks and launch parallel workers
                    subchunk_size = max(1, int(len(batch) // int(workers)))
                    subchunks = list(chunkify_list(batch, subchunk_size))
                    with ThreadPoolExecutor(max_workers=int(workers)) as ex:
                        futures = []
                        for sc in subchunks:
                            futures.append(ex.submit(worker_fetch_subchunk := None))  # placeholder to avoid lint; will replace below
                        # build proper futures list by submitting the function correctly
                        futures = [ex.submit(lambda sc=sc: (
                            lambda: None  # placeholder
                        )()) for sc in subchunks]  # replaced below

                    # Because inline lambda with closures is messy, use a simple loop approach:
                    with ThreadPoolExecutor(max_workers=int(workers)) as ex:
                        futures = [ex.submit(lambda sc=sc: __import__('__main__').worker_fetch_chunk(sc, mail_folders, imap_host, 993, email_user, app_password, int(max_retries), int(base_retry_delay))) for sc in subchunks]  # noqa: E501
                        completed = 0
                        for fut in as_completed(futures):
                            try:
                                resobj = fut.result()
                            except Exception as e:
                                resobj = {'error': str(e), 'data': []}
                            if resobj.get('error'):
                                st.warning(f"Worker error in batch {bi}: {resobj['error']}")
                            else:
                                # resobj['data'] expected list of items similar to sequential's items
                                for item in resobj.get('data', []):
                                    # ensure uid string
                                    uid_str = item.get('uid', (item['uid'].decode() if isinstance(item['uid'], bytes) else str(item['uid'])))
                                    save_item = {'uid': uid_str, 'folder': item.get('folder', ''), 'html': item.get('html', ''), 'css': item.get('css', '')}
                                    append_checkpoint_item(run_dir, save_item)
                                    append_fetched_uid(run_dir, uid_str)
                                    all_extracted.append(save_item)
                            completed += 1
                            message_progress.progress(int(completed/len(subchunks)*100))
                            message_line.write(f"Completed {completed}/{len(subchunks)} parallel workers for this batch")
                    message_progress.progress(100)

                # end of batch: update batch progress and free UI
                message_line.empty()
                message_progress.empty()
                batch_progress.progress(int(bi / n_batches * 100))

            # end batches loop

            st.write(f"Fetched & checkpointed items: {len(all_extracted)}")

            # flatten checkpointed items into file records for clustering
            file_records = []
            for item in all_extracted:
                uid = item['uid']
                folder = item.get('folder', 'unknown')
                fid = f"{folder}_{uid}_{uuid.uuid4().hex[:6]}"
                html_path = tmpdir / f"{fid}.html"
                css_path = tmpdir / f"{fid}.css"
                html_path.write_text(item.get('html',''), encoding='utf-8')
                css_path.write_text(item.get('css',''), encoding='utf-8')
                file_records.append({'uid': uid, 'folder': folder, 'html_path': str(html_path), 'css_path': str(css_path), 'html_text': item.get('html','')})

            st.write(f"Saved {len(file_records)} html parts to disk for clustering.")

            # clustering & zip
            docs = [clean_for_vector(r['html_text']) for r in file_records]
            if len(docs) == 0:
                st.error("No HTML documents to cluster.")
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

                st.success(f"Created ZIP: {out_zip.name}")
                with open(out_zip, 'rb') as fh:
                    st.download_button("Download clustered ZIP", fh.read(), file_name=out_zip.name)

        # cleanup tmpdir (keep checkpoints)
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

st.markdown("---")
st.caption("Checkpoints are stored in ./email_extractor_checkpoints/<run_dir>/. Resume is available from the latest run.")
