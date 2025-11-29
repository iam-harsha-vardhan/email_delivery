# Streamlit app: Email HTML Extractor, De-encoder, and Clustering Zipper
# Save as: streamlit_email_html_extractor.py
# Requirements: pip install streamlit beautifulsoup4 lxml scikit-learn numpy pandas joblib
# Optional for better performance: pip install python-magic

import streamlit as st
import imaplib
import email
from email.header import decode_header
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
from joblib import Parallel, delayed

st.set_page_config(page_title="Email HTML Extractor & Cluster Zipper", layout="wide")
st.title("Email HTML Extractor — decode, cluster, zip")

st.markdown(
    """
Provide an email (IMAP) account and app password. The app will pull HTML creatives from the selected mailbox/folder,
attempt to decode encoded parts (base64, quoted-printable), extract HTML + CSS, cluster similar templates into batches,
and produce a final ZIP containing subfolders for each cluster.

**Security:** your credentials are used only for the running session. For Gmail use an AppPassword or OAuth IMAP token — do not paste your regular password if 2FA is enabled.
"""
)

with st.sidebar.form("connection_form"):
    imap_host = st.text_input("IMAP host (e.g. imap.gmail.com)", value="imap.gmail.com")
    imap_port = st.number_input("IMAP port", value=993)
    email_user = st.text_input("Email (username)")
    app_password = st.text_input("App password / IMAP password", type="password")
    mail_folder = st.text_input("Mailbox/folder", value="INBOX")
    search_query = st.text_input("IMAP search query (e.g. ALL, UNSEEN, SINCE 01-Jan-2024)", value="ALL")
    max_messages = st.number_input("Max messages to fetch (0 = all)", min_value=0, value=0)
    workers = st.number_input("Parallel workers (instances)", min_value=1, max_value=32, value=4)
    cluster_mode = st.selectbox("Clustering mode", ["Fixed clusters (n)", "Distance threshold"], index=0)
    if cluster_mode == "Fixed clusters (n)":
        n_clusters = st.number_input("Number of clusters (n)", min_value=1, value=10)
        distance_threshold = None
    else:
        distance_threshold = st.number_input("Linkage distance threshold (smaller = more clusters)", min_value=0.0, value=1.5, step=0.1)
        n_clusters = None
    submit = st.form_submit_button("Start extraction & clustering")

# helpers

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
            # email package can decode if we ask for decode=True
            decoded = part.get_payload(decode=True)
            if decoded is None:
                decoded = content.encode('utf-8', errors='ignore') if isinstance(content, str) else content
    except Exception:
        # fallback
        decoded = content if isinstance(content, bytes) else str(content).encode('utf-8', errors='ignore')
    return decoded


def extract_html_and_css_from_message(msg_bytes):
    # msg_bytes: raw bytes
    try:
        msg = email.message_from_bytes(msg_bytes)
    except Exception:
        return []

    results = []
    # walk parts
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == 'text/html' or (ctype == 'text/plain' and part.get_content_charset() is None and '<html' in (part.get_payload(decode=True) or b'').decode('utf-8', errors='ignore').lower()):
            decoded = decode_part(part)
            if not decoded:
                continue
            try:
                html = decoded.decode(part.get_content_charset() or 'utf-8', errors='ignore') if isinstance(decoded, (bytes, bytearray)) else str(decoded)
            except Exception:
                html = decoded.decode('utf-8', errors='ignore') if isinstance(decoded, (bytes, bytearray)) else str(decoded)
            soup = BeautifulSoup(html, 'lxml')
            # extract style blocks
            styles = ''.join([s.get_text() for s in soup.find_all('style')])
            # remove inline data and scripts to keep template structure
            for tag in soup.find_all(['script']):
                tag.decompose()
            # remove src/href values to reduce noise
            for t in soup.find_all(True):
                if t.has_attr('src'):
                    del t['src']
                if t.has_attr('href'):
                    del t['href']
                # remove id/class values (optional) to reduce noise
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
    # collapse whitespace
    txt = re.sub(r'\s+', ' ', txt)
    return txt


def fetch_message_by_uid(imap, uid):
    # returns raw bytes
    res, data = imap.uid('fetch', uid, '(RFC822)')
    if res != 'OK':
        return None
    return data[0][1]


def process_uids_segment(uids, imap_host, imap_port, user, pwd, folder):
    """Connects, fetches and extracts html parts for a segment of uids. Returns list of dict with uid and parts."""
    results = []
    try:
        imap = imaplib.IMAP4_SSL(imap_host, imap_port)
        imap.login(user, pwd)
        imap.select(folder)
    except Exception as e:
        return {'error': str(e), 'data': []}

    for uid in uids:
        raw = fetch_message_by_uid(imap, uid)
        if not raw:
            continue
        parts = extract_html_and_css_from_message(raw)
        if parts:
            results.append({'uid': uid, 'parts': parts})
    try:
        imap.logout()
    except Exception:
        pass
    return {'error': None, 'data': results}


def chunkify(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]


if submit:
    if not (email_user and app_password and imap_host):
        st.error("Provide IMAP host, email and app password.")
    else:
        tmpdir = Path(tempfile.mkdtemp(prefix='email_html_extract_'))
        st.info(f"Working directory: {tmpdir}")
        progress_bar = st.progress(0)
        status = st.empty()

        try:
            imap = imaplib.IMAP4_SSL(imap_host, imap_port)
            imap.login(email_user, app_password)
            imap.select(mail_folder)
            res, data = imap.uid('search', None, search_query)
            if res != 'OK':
                st.error('IMAP search failed: ' + str(res))
            else:
                uids = data[0].split()
                if max_messages and max_messages > 0:
                    uids = uids[:int(max_messages)]
                total = len(uids)
                status.write(f"Found {total} messages matching query. Processing with {workers} workers...")

                # split uids into worker chunks for independent IMAP connections
                chunks = list(chunkify(uids, max(1, len(uids)//workers)))
                extracted = []
                processed = 0

                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [executor.submit(process_uids_segment, chunk, imap_host, imap_port, email_user, app_password, mail_folder) for chunk in chunks]
                    for fut in as_completed(futures):
                        resobj = fut.result()
                        if resobj.get('error'):
                            st.warning('Worker error: ' + resobj['error'])
                        for item in resobj['data']:
                            extracted.append(item)
                        processed += 1
                        # update progress roughly by chunk completion
                        progress_bar.progress(min(100, int(processed/len(chunks)*100)))

                st.write(f"Extracted HTML parts from {len(extracted)} messages (messages that had HTML).")

                # flatten parts into files
                file_records = []  # each record: {'uid','index','html','css','filename_html'}
                for msg in extracted:
                    uid = msg['uid'].decode() if isinstance(msg['uid'], bytes) else str(msg['uid'])
                    for idx, part in enumerate(msg['parts']):
                        fid = f"{uid}_{idx}_{uuid.uuid4().hex[:6]}"
                        html_name = tmpdir / f"{fid}.html"
                        css_name = tmpdir / f"{fid}.css"
                        html_text = part['html']
                        css_text = part['css'] or ''
                        html_name.write_text(html_text, encoding='utf-8')
                        css_name.write_text(css_text, encoding='utf-8')
                        file_records.append({'uid': uid, 'index': idx, 'html_path': str(html_name), 'css_path': str(css_name), 'html_text': html_text})

                st.write(f"Saved {len(file_records)} html parts to disk.")

                # clustering preparation
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
                        # Agglomerative with distance threshold: scikit-learn <1.2 uses distance_threshold param differently; we'll use n_clusters=None
                        model = AgglomerativeClustering(n_clusters=None, distance_threshold=float(distance_threshold), affinity='euclidean', linkage='ward')

                    labels = model.fit_predict(X.toarray())

                    # create cluster folders and move files
                    clusters = {}
                    for rec, lab in zip(file_records, labels):
                        clusters.setdefault(int(lab), []).append(rec)

                    out_zip_path = tmpdir / f"email_templates_clusters_{uuid.uuid4().hex[:8]}.zip"
                    with zipfile.ZipFile(out_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for lab, items in clusters.items():
                            folder_name = f"cluster_{lab}"
                            for it in items:
                                # add html
                                arc_html = str(Path(folder_name) / Path(it['html_path']).name)
                                zf.write(it['html_path'], arc_html)
                                # add css if non-empty
                                if os.path.exists(it['css_path']) and Path(it['css_path']).stat().st_size > 0:
                                    arc_css = str(Path(folder_name) / Path(it['css_path']).name)
                                    zf.write(it['css_path'], arc_css)

                    st.success(f"Created ZIP with {len(clusters)} clusters: {out_zip_path}")

                    # provide download
                    with open(out_zip_path, 'rb') as fh:
                        btn = st.download_button(label='Download clustered ZIP', data=fh.read(), file_name=out_zip_path.name)

        except Exception as e:
            st.exception(e)
        finally:
            try:
                shutil.rmtree(tmpdir)
            except Exception:
                pass

st.markdown("---")
st.caption('Notes: This script is a practical starter. For mailboxes with tens of thousands of messages, run on a machine with sufficient memory and consider using a job queue / chunked persistence. Clustering quality will improve if you further normalize templates (remove timestamps, numbers, GUIDs) and tune vectorizer parameters.')
