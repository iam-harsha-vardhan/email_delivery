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
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- Page ----------

st.set_page_config(page_title="Dynamic Multi-Account Inbox Comparator", layout="wide")
st.title("📧 Dynamic Multi-Account Inbox Comparator")

# ---------- Config ----------

CHUNK_SIZE = 150

# ---------- Session State ----------

if "creds_df" not in st.session_state:
st.session_state.creds_df = pd.DataFrame([{"Email": "", "Password": ""}])

if "mailbox_data" not in st.session_state:
st.session_state.mailbox_data = {}

if "batch_id" not in st.session_state:
st.session_state.batch_id = 0

# ---------- Helpers ----------

def get_empty_mailbox_structure():
return {
"last_uid": None,
"df": pd.DataFrame(columns=[
"UID","Domain","Subject","From","Message-ID",
"Date","Date_dt","Sub ID","Type",
"SPF","DKIM","DMARC","fetch_batch"
])
}

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

def extract_domain_from_address(addr):
m = re.search(r'@([\w.-]+)', addr or "")
return m.group(1).lower() if m else "-"

def extract_auth_results(msg):
auth = msg.get("Authentication-Results", "")
spf = dkim = dmarc = "neutral"

```
m = re.search(r'spf=(\w+)', auth, re.I)
if m: spf = m.group(1).lower()

m = re.search(r'dkim=(\w+)', auth, re.I)
if m: dkim = m.group(1).lower()

m = re.search(r'dmarc=(\w+)', auth, re.I)
if m: dmarc = m.group(1).lower()

return spf, dkim, dmarc
```

ID_RE = re.compile(r'\b(GRM-[A-Za-z0-9-]+|GMFP-[A-Za-z0-9-]+|GTC-[A-Za-z0-9-]+|GRTC-[A-Za-z0-9-]+)\b', re.I)

def extract_subid(msg):

```
msgid = msg.get("Message-ID","")

m = ID_RE.search(msgid)
if m:
    return m.group(1)

for part in msg.walk():

    if part.get_content_type() in ["text/plain","text/html"]:
        payload = part.get_payload(decode=True)
        if not payload:
            continue

        try:
            text = payload.decode("utf-8","ignore")
        except:
            continue

        m = ID_RE.search(text)
        if m:
            return m.group(1)

return "-"
```

def format_date(raw):

```
if not raw:
    return "-",None

try:
    dt = parsedate_to_datetime(raw)
except:
    return raw,None

if dt.tzinfo is None:
    dt = dt.replace(tzinfo=datetime.timezone.utc)

ist = pytz.timezone("Asia/Kolkata")
dt = dt.astimezone(ist)
return dt.strftime("%d-%b-%Y %I:%M %p"), dt.replace(tzinfo=None)
```

# ---------- UIDNEXT ----------

def get_uidnext(imap):

```
try:
    status,data = imap.status("INBOX","(UIDNEXT)")
    if status == "OK":
        txt = data[0].decode()
        m = re.search(r'UIDNEXT (\d+)',txt)
        if m:
            return int(m.group(1))
except:
    pass

return None
```

# ---------- Fetch Function ----------

def fetch_inbox(email_addr,password,last_uid=None,fetch_n=None,fetch_unit="emails"):

```
results=[]
new_last_uid = last_uid

try:

    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(email_addr,password)
    imap.select("INBOX")

    uids=[]

    # ---------- Incremental using UIDNEXT ----------

    if fetch_unit=="incremental":

        uidnext = get_uidnext(imap)

        if last_uid and uidnext:

            start = int(last_uid)+1
            end = uidnext-1

            if start<=end:

                status,data = imap.uid("search",None,f"UID {start}:{end}")

                if status=="OK" and data and data[0]:
                    uids=data[0].split()

    # ---------- Fetch Last N Emails ----------

    elif fetch_unit=="emails":

        status,data = imap.uid("search",None,"ALL")

        if status=="OK" and data and data[0]:

            all_uids=data[0].split()
            uids = all_uids[-int(fetch_n):]


    # ---------- Fetch Last N Minutes/Hours ----------

    else:

        ist=pytz.timezone("Asia/Kolkata")
        now=datetime.datetime.now(ist)

        if fetch_unit=="minutes":
            cutoff = now-datetime.timedelta(minutes=int(fetch_n))
        else:
            cutoff = now-datetime.timedelta(hours=int(fetch_n))

        status,data = imap.uid("search",None,"ALL")

        if status=="OK" and data and data[0]:

            all_uids=data[0].split()

            for uid in all_uids[::-1]:

                res,msgdata = imap.uid("fetch",uid,"(BODY.PEEK[HEADER.FIELDS (DATE)])")

                if res!="OK":
                    continue

                raw = msgdata[0][1].decode()

                m=re.search(r'Date:\s*(.+)',raw)

                if not m:
                    continue

                _,dt = format_date(m.group(1))

                if dt and dt>=cutoff.replace(tzinfo=None):
                    uids.append(uid)
                else:
                    break


    # ---------- Fetch Headers ----------

    for i in range(0,len(uids),CHUNK_SIZE):

        chunk=uids[i:i+CHUNK_SIZE]
        seq=b",".join(chunk)

        res,data = imap.uid("fetch",seq,"(BODY.PEEK[HEADER])")

        if res!="OK":
            continue

        for part in data:

            if not isinstance(part,tuple):
                continue

            meta = part[0].decode(errors="ignore")
            m=re.search(r'UID (\d+)',meta)

            if not m:
                continue

            uid=m.group(1)

            msg=email.message_from_bytes(part[1])

            subject=decode_mime_words(msg.get("Subject",""))
            from_h=decode_mime_words(msg.get("From",""))

            domain=extract_domain_from_address(from_h)

            spf,dkim,dmarc = extract_auth_results(msg)

            subid = extract_subid(msg)

            date_raw = msg.get("Date","")
            date_str,date_dt = format_date(date_raw)

            results.append({
                "UID":uid,
                "Domain":domain,
                "Subject":subject,
                "From":from_h,
                "Message-ID":msg.get("Message-ID",""),
                "Date":date_str,
                "Date_dt":date_dt,
                "Sub ID":subid,
                "Type":"-",
                "SPF":spf,
                "DKIM":dkim,
                "DMARC":dmarc
            })

            if new_last_uid is None or int(uid)>int(new_last_uid):
                new_last_uid=uid

    imap.logout()

except Exception as e:
    st.error(f"{email_addr} error: {e}")

return pd.DataFrame(results), new_last_uid
```

# ---------- Fetch Controller ----------

def process_fetch(fetch_type,fetch_n=None,fetch_unit="emails"):

```
st.session_state.batch_id += 1
batch_id = st.session_state.batch_id

accounts=[]

for _,r in st.session_state.creds_df.iterrows():

    email_addr=r.get("Email","").strip()
    pwd=r.get("Password","").strip()

    if email_addr and pwd:

        if email_addr not in st.session_state.mailbox_data:
            st.session_state.mailbox_data[email_addr]=get_empty_mailbox_structure()

        accounts.append((email_addr,pwd))

def worker(acc):

    email_addr,pwd = acc

    mailbox = st.session_state.mailbox_data[email_addr]

    df,new_uid = fetch_inbox(
        email_addr,
        pwd,
        mailbox["last_uid"],
        fetch_n,
        fetch_unit
    )

    return email_addr,df,new_uid

with ThreadPoolExecutor(max_workers=len(accounts)) as exe:

    futures=[exe.submit(worker,a) for a in accounts]

    for f in as_completed(futures):

        email_addr,df,new_uid=f.result()

        mailbox=st.session_state.mailbox_data[email_addr]

        if not df.empty:

            df["fetch_batch"]=batch_id

            mailbox["df"]=pd.concat(
                [mailbox["df"],df],
                ignore_index=True
            ).drop_duplicates(subset=["UID"],keep="last")

            try:
                mailbox["last_uid"]=str(mailbox["df"]["UID"].astype(int).max())
            except:
                pass
```

# ---------- Row Coloring ----------

def highlight_rows(row):

```
if row.get("fetch_batch")==st.session_state.batch_id:
    return ["background-color:#90EE90"]*len(row)

return [""]*len(row)
```

# ---------- Credentials UI ----------

st.markdown("### 📋 Accounts")

edited = st.data_editor(
st.session_state.creds_df,
num_rows="dynamic",
use_container_width=True,
hide_index=True
)

st.session_state.creds_df=edited

# ---------- Controls ----------

st.markdown("---")

col1,col2,col3 = st.columns([1,2,1])

with col1:

```
if st.button("🔄 Fetch New"):

    process_fetch("incremental",None,"incremental")
    st.success("Incremental fetch done")
```

with col2:

```
n = st.number_input("N",1,500,100)

unit = st.selectbox(
    "Unit",
    ["emails","minutes","hours"]
)

if st.button("📥 Fetch Last N"):

    process_fetch("last",n,unit)
    st.success("Fetched")
```

with col3:

```
if st.button("🗑 Clear"):

    st.session_state.mailbox_data={}
    st.rerun()
```

st.markdown("---")

# ---------- Raw Inbox Tables ----------

for email_addr,data in st.session_state.mailbox_data.items():

```
st.subheader(email_addr)

df=data["df"]

if not df.empty:

    show=df.sort_values(
        ["fetch_batch","Date_dt"],
        ascending=[False,False]
    )

    st.dataframe(
        show.style.apply(highlight_rows,axis=1),
        use_container_width=True,
        hide_index=True
    )
```
