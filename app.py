```python
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
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- Page ----------
st.set_page_config(page_title="Dynamic Multi-Account Inbox Comparator", layout="wide")
st.title("📧 Dynamic Multi-Account Inbox Comparator")

# ---------- Config ----------
UID_SCAN_LIMIT = 2000
CHUNK_SIZE = 150

# ---------- Session ----------
if "creds_df" not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{"Email": "", "Password": ""}])

if "mailbox_data" not in st.session_state:
    st.session_state.mailbox_data = {}

if "batch_id" not in st.session_state:
    st.session_state.batch_id = 0

# ---------- Mailbox Structure ----------
def get_empty_mailbox_structure():
    return {
        "last_uid": None,
        "df": pd.DataFrame(columns=[
            "UID","Domain","Subject","From","Message-ID","Date",
            "Date_dt","Sub ID","Type","SPF","DKIM","DMARC","fetch_batch"
        ])
    }

# ---------- Helpers ----------
def decode_mime_words(s):
    if not s:
        return ""
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

def extract_domain_from_address(address):
    if not address:
        return "-"
    m = re.search(r'@([\w\.-]+)', address)
    return m.group(1).lower() if m else "-"

def extract_auth_results_from_headers(msg):
    auth = msg.get("Authentication-Results", "") or ""
    spf = dkim = dmarc = "neutral"

    m = re.search(r'spf=(\w+)', auth, re.I)
    if m: spf = m.group(1).lower()

    m = re.search(r'dkim=(\w+)', auth, re.I)
    if m: dkim = m.group(1).lower()

    m = re.search(r'dmarc=(\w+)', auth, re.I)
    if m: dmarc = m.group(1).lower()

    return spf, dkim, dmarc

ID_RE = re.compile(r'\b(GRM-[A-Za-z0-9\-]+|GMFP-[A-Za-z0-9\-]+|GTC-[A-Za-z0-9\-]+|GRTC-[A-Za-z0-9\-]+)\b', re.I)

def map_id_to_type(sub_id):
    if not sub_id: return "-"
    s=sub_id.lower()
    if s.startswith("grm"): return "FPR"
    if s.startswith("gmfp"): return "FP"
    if s.startswith("gtc"): return "FPTC"
    if s.startswith("grtc"): return "FPRTC"
    return "-"

def find_subid_in_text(txt):
    if not txt:
        return None
    m=ID_RE.search(txt)
    return m.group(1) if m else None

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
    return dt_ist.strftime("%d-%b-%Y %I:%M %p"), dt_ist.replace(tzinfo=None)

def extract_subid_from_msg(msg):

    msgid = msg.get("Message-ID","")

    tokens = re.split(r'[_\s]+', msgid)

    for t in tokens:
        s = find_subid_in_text(t)
        if s:
            return s, map_id_to_type(s)

    for h,v in msg.items():
        s=find_subid_in_text(str(v))
        if s:
            return s,map_id_to_type(s)

    return None,"-"

# ---------- UIDNEXT ----------
def get_uidnext(imap):
    try:
        status, data = imap.status("INBOX","(UIDNEXT)")
        if status=="OK":
            txt=data[0].decode()
            m=re.search(r'UIDNEXT (\d+)',txt)
            if m:
                return int(m.group(1))
    except:
        pass
    return None

# ---------- Fetch ----------
def fetch_inbox_emails_single(email_addr,password,last_uid=None,fetch_n=None,fetch_unit="emails"):

    results=[]
    new_last_uid=last_uid

    imap=imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(email_addr,password)
    imap.select("INBOX")

    uids=[]

    if last_uid:

        uidnext=get_uidnext(imap)

        if uidnext:
            start=int(last_uid)+1
            end=uidnext-1

            if start<=end:

                status,data=imap.uid("search",None,f"UID {start}:{end}")

                if status=="OK" and data and data[0]:
                    uids=data[0].split()

    if fetch_unit=="emails" and fetch_n:

        status,data=imap.uid("search",None,"ALL")

        if status=="OK" and data and data[0]:
            all_uids=data[0].split()
            uids=all_uids[-int(fetch_n):]

    if not uids:
        imap.logout()
        return pd.DataFrame(results),new_last_uid

    for i in range(0,len(uids),CHUNK_SIZE):

        chunk=uids[i:i+CHUNK_SIZE]
        uid_seq=b",".join(chunk)

        res,data=imap.uid("fetch",uid_seq,"(BODY.PEEK[HEADER])")

        for part in data:

            if not isinstance(part,tuple):
                continue

            msg=email.message_from_bytes(part[1])

            meta=part[0].decode("utf-8","ignore")

            m=re.search(r'UID\s+(\d+)',meta)

            if not m:
                continue

            uid=m.group(1)

            subject=decode_mime_words(msg.get("Subject",""))
            from_h=decode_mime_words(msg.get("From",""))

            domain=extract_domain_from_address(from_h)

            spf,dkim,dmarc=extract_auth_results_from_headers(msg)

            subid,typ=extract_subid_from_msg(msg)

            raw_date=msg.get("Date","")

            formatted,dt=format_date_to_ist_string(raw_date)

            results.append({
                "UID":uid,
                "Domain":domain,
                "Subject":subject,
                "From":from_h,
                "Message-ID":msg.get("Message-ID",""),
                "Date":formatted,
                "Date_dt":dt,
                "Sub ID":subid or "-",
                "Type":typ,
                "SPF":spf,
                "DKIM":dkim,
                "DMARC":dmarc
            })

            if new_last_uid is None or int(uid)>int(new_last_uid):
                new_last_uid=uid

    imap.logout()

    return pd.DataFrame(results),new_last_uid

# ---------- Parallel Fetch ----------
def process_fetch(fetch_type,fetch_n=None,fetch_unit="emails"):

    st.session_state.batch_id+=1
    batch=st.session_state.batch_id

    accounts=[]

    for _,r in st.session_state.creds_df.iterrows():

        e=r.get("Email","").strip()
        p=r.get("Password","").strip()

        if not e or not p:
            continue

        if e not in st.session_state.mailbox_data:
            st.session_state.mailbox_data[e]=get_empty_mailbox_structure()

        accounts.append((e,p))

    def worker(e,p):

        mailbox=st.session_state.mailbox_data[e]

        df_new,new_uid=fetch_inbox_emails_single(
            e,p,
            last_uid=mailbox.get("last_uid"),
            fetch_n=fetch_n,
            fetch_unit=fetch_unit
        )

        return e,df_new,new_uid

    with ThreadPoolExecutor(max_workers=len(accounts)) as executor:

        futures=[executor.submit(worker,a,b) for a,b in accounts]

        for future in as_completed(futures):

            e,df_new,new_uid=future.result()

            mailbox=st.session_state.mailbox_data[e]

            if not df_new.empty:

                df_new["fetch_batch"]=batch

                mailbox["df"]=pd.concat(
                    [mailbox["df"],df_new],
                    ignore_index=True
                ).drop_duplicates(subset=["UID"],keep="last")

                try:
                    mailbox["last_uid"]=str(mailbox["df"]["UID"].astype(int).max())
                except:
                    pass

# ---------- Row Styling ----------
def highlight_new_rows(row):

    if row.get("fetch_batch")==st.session_state.batch_id:
        return ["background-color:#90EE90"]*len(row)

    return [""]*len(row)

# ---------- Credentials ----------
st.markdown("### 📋 Account Credentials")

edited=st.data_editor(
    st.session_state.creds_df,
    num_rows="dynamic",
    use_container_width=True,
    hide_index=True
)

st.session_state.creds_df=edited

# ---------- Controls ----------
col1,col2=st.columns(2)

with col1:
    if st.button("🔄 Fetch New"):
        process_fetch("incremental")
        st.success("Fetched new emails")

with col2:

    n=st.number_input("N",1,1000,100)

    if st.button("📥 Fetch Last N Emails"):
        process_fetch("last_n",n,"emails")
        st.success("Fetched last N")

st.markdown("---")

# ---------- Table ----------
rows=[]

for acc,data in st.session_state.mailbox_data.items():

    df=data["df"]

    for _,r in df.iterrows():

        row=r.to_dict()

        row["Account"]=acc.split("@")[0]

        rows.append(row)

if rows:

    df=pd.DataFrame(rows)

    df=df.sort_values("Date_dt",ascending=False)

    st.dataframe(
        df.style.apply(highlight_new_rows,axis=1),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No emails yet")
```
