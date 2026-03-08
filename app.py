# app.py

import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
import datetime
import re
import pandas as pd
import pytz
import base64
import binascii
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------- Basic page ----------
st.set_page_config(page_title="Dynamic Multi-Account Inbox Comparator", layout="wide")
st.title("📧 Dynamic Multi-Account Inbox Comparator")

# ---------- Config ----------
UID_SCAN_LIMIT = 2000
CHUNK_SIZE = 200
MAX_PARALLEL_IMAP = 5


# ---------- Session State ----------
if "creds_df" not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{"Email": "", "Password": ""}])

if "mailbox_data" not in st.session_state:
    st.session_state.mailbox_data = {}


# ---------- Mailbox Structure ----------
def get_empty_mailbox_structure():
    return {
        "last_uid": None,
        "df": pd.DataFrame(columns=[
            "UID","Domain","Subject","From","Message-ID","Date","Date_dt",
            "Sub ID","Type","SPF","DKIM","DMARC","is_new"
        ])
    }


# ---------- Utilities ----------
def decode_mime_words(s):
    if not s: return ""
    decoded = ""
    for word, enc in decode_header(s):
        if isinstance(word, bytes):
            try:
                decoded += word.decode(enc or "utf-8", errors="ignore")
            except:
                decoded += word.decode("utf-8", errors="ignore")
        else:
            decoded += word
    return decoded.strip()


def extract_domain_from_address(addr):
    if not addr: return "-"
    m = re.search(r'@([\w\.-]+)', addr)
    return m.group(1).lower() if m else "-"


def extract_auth_results_from_headers(msg):
    auth = msg.get("Authentication-Results","") or " ".join(f"{h}:{v}" for h,v in msg.items())

    spf = dkim = dmarc = "neutral"

    m = re.search(r'spf=(\w+)', auth, re.I)
    if m: spf = m.group(1).lower()

    m = re.search(r'dkim=(\w+)', auth, re.I)
    if m: dkim = m.group(1).lower()

    m = re.search(r'dmarc=(\w+)', auth, re.I)
    if m: dmarc = m.group(1).lower()

    return spf, dkim, dmarc


# ---------- Sub ID detection ----------
ID_RE = re.compile(r'\b(GRM-[A-Za-z0-9\-]+|GMFP-[A-Za-z0-9\-]+|GTC-[A-Za-z0-9\-]+|GRTC-[A-Za-z0-9\-]+)\b', re.I)

def map_id_to_type(sub_id):

    if not sub_id:
        return "-"

    lid = sub_id.lower()

    if lid.startswith("grm"):
        return "FPR"

    if lid.startswith("gmfp"):
        return "FP"

    if lid.startswith("gtc"):
        return "FPTC"

    if lid.startswith("grtc"):
        return "FPRTC"

    return "-"


# ---------- Date ----------
def format_date_to_ist_string(raw_date):

    if not raw_date:
        return "-", None

    try:
        dt = parsedate_to_datetime(raw_date)
    except:
        return raw_date, None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)

    ist = pytz.timezone("Asia/Kolkata")

    dt_ist = dt.astimezone(ist)

    dt_naive = dt_ist.replace(tzinfo=None)

    formatted = dt_ist.strftime("%d-%b-%Y %I:%M %p")

    return formatted, dt_naive


# ---------- UIDNEXT detection ----------
def get_uidnext(imap):

    status, data = imap.select("inbox")

    if status != "OK":
        return None

    try:
        txt = data[0].decode()
    except:
        return None

    m = re.search(r'UIDNEXT (\d+)', txt)

    if m:
        return int(m.group(1))

    return None


# ---------- Core fetch ----------
def fetch_inbox_emails_single(email_addr, password, last_uid=None,
                              fetch_n=None, fetch_unit="emails",
                              uid_scan_limit=UID_SCAN_LIMIT,
                              chunk_size=CHUNK_SIZE):

    results = []
    new_last_uid = last_uid

    try:

        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_addr, password)

        imap.select("inbox")

        uidnext = get_uidnext(imap)

        # ---------- Incremental ----------
        if last_uid and uidnext:

            start = int(last_uid) + 1
            end = uidnext - 1

            if end >= start:

                status, data = imap.uid("search", None, f"UID {start}:{end}")

                uids = data[0].split() if status == "OK" else []

            else:
                uids = []

        else:

            status, data = imap.uid("search", None, "ALL")

            if status == "OK" and data and data[0]:

                all_uids = data[0].split()

                uids = all_uids[-uid_scan_limit:]

            else:
                uids = []


        if not uids:
            imap.logout()
            return pd.DataFrame(results), new_last_uid


        for i in range(0, len(uids), chunk_size):

            chunk = uids[i:i+chunk_size]

            uid_seq = b",".join(chunk)

            res, fdata = imap.uid("fetch", uid_seq, "(BODY.PEEK[HEADER])")

            if res != "OK":
                continue

            for part in fdata:

                if not isinstance(part, tuple):
                    continue

                try:
                    msg = email.message_from_bytes(part[1])
                except:
                    continue

                meta = part[0].decode(errors="ignore")

                m = re.search(r"UID\s+(\d+)", meta)

                if not m:
                    continue

                uid_str = m.group(1)

                subject = decode_mime_words(msg.get("Subject","No Subject"))
                from_h = decode_mime_words(msg.get("From","-"))

                domain = extract_domain_from_address(from_h)

                spf,dkim,dmarc = extract_auth_results_from_headers(msg)

                raw_date = msg.get("Date","")

                formatted,dt = format_date_to_ist_string(raw_date)

                results.append({
                    "UID":uid_str,
                    "Domain":domain,
                    "Subject":subject,
                    "From":from_h,
                    "Message-ID":decode_mime_words(msg.get("Message-ID","")),
                    "Date":formatted,
                    "Date_dt":dt,
                    "Sub ID":"-",
                    "Type":"-",
                    "SPF":spf,
                    "DKIM":dkim,
                    "DMARC":dmarc
                })

                if new_last_uid is None or int(uid_str) > int(new_last_uid):
                    new_last_uid = uid_str

        imap.logout()

    except Exception as e:
        st.error(f"{email_addr}: {e}")
        return pd.DataFrame(), last_uid

    df = pd.DataFrame(results)

    return df, new_last_uid


# ---------- Styling ----------
def highlight_new_rows(row):
    return ["background-color:#90EE90"]*len(row) if row.get("is_new",False) else [""]*len(row)


# ---------- UI ----------
st.markdown("### 📋 Account Credentials")

edited_df = st.data_editor(
    st.session_state.creds_df,
    num_rows="dynamic",
    hide_index=True,
    use_container_width=True
)

st.session_state.creds_df = edited_df


# ---------- Parallel Fetch ----------
def process_fetch(fetch_type, fetch_n=None, fetch_unit="emails"):

    # clear previous batch markers
    for mailbox in st.session_state.mailbox_data.values():
        if "is_new" in mailbox["df"].columns:
            mailbox["df"]["is_new"] = False

    tasks = []

    for _, r in st.session_state.creds_df.iterrows():

        email_addr = r.get("Email","").strip()
        pwd = r.get("Password","").strip()

        if not email_addr or not pwd:
            continue

        if email_addr not in st.session_state.mailbox_data:
            st.session_state.mailbox_data[email_addr] = get_empty_mailbox_structure()

        mailbox = st.session_state.mailbox_data[email_addr]

        tasks.append((email_addr,pwd,mailbox))

    if not tasks:
        return False


    with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_IMAP,len(tasks))) as executor:

        futures = {}

        for email_addr,pwd,mailbox in tasks:

            future = executor.submit(
                fetch_inbox_emails_single,
                email_addr,
                pwd,
                mailbox.get("last_uid"),
                fetch_n,
                fetch_unit
            )

            futures[future] = (email_addr,mailbox)


        for future in as_completed(futures):

            email_addr,mailbox = futures[future]

            try:

                df_new,new_uid = future.result()

                if not df_new.empty:

                    df_new["is_new"] = True

                    mailbox["df"] = pd.concat(
                        [mailbox["df"],df_new],
                        ignore_index=True
                    ).drop_duplicates(subset=["UID"],keep="last")

                    mailbox["last_uid"] = new_uid

            except Exception as e:

                st.error(f"{email_addr} thread error: {e}")

    return True


# ---------- Control ----------
col1,col2 = st.columns(2)

with col1:

    if st.button("🔄 Fetch New (incremental)"):
        ok = process_fetch("incremental")
        if ok:
            st.success("Fetched new emails")

with col2:

    if st.button("🗑️ Clear All"):
        st.session_state.mailbox_data={}
        st.rerun()


# ---------- Table ----------
st.markdown("---")
st.subheader("📋 Email Presence Table")


rows=[]

for email_addr,mailbox in st.session_state.mailbox_data.items():

    for _,r in mailbox["df"].iterrows():

        rows.append(r)


if rows:

    df = pd.DataFrame(rows)

    df = df.sort_values(by="Date_dt",ascending=False)

    st.dataframe(
        df.style.apply(highlight_new_rows,axis=1),
        hide_index=True,
        use_container_width=True
    )

else:

    st.info("No emails yet")
