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

# ---------------- PAGE ----------------

st.set_page_config(page_title="Dynamic Multi-Account Inbox Comparator", layout="wide")
st.title("📧 Dynamic Multi-Account Inbox Comparator")

MAX_WORKERS = 4   # safe parallelism for IMAP

# ---------------- SESSION STATE ----------------

if "creds_df" not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{"Email": "", "Password": ""}])

if "mailbox_data" not in st.session_state:
    st.session_state.mailbox_data = {}

if "fetch_batch_id" not in st.session_state:
    st.session_state.fetch_batch_id = 0


# ---------------- DATA STRUCTURE ----------------

def get_empty_mailbox_structure():
    return {
        "last_uid": None,
        "df": pd.DataFrame(columns=[
            "UID","Domain","Subject","From","Message-ID",
            "Date","Date_dt","Sub ID","Type",
            "SPF","DKIM","DMARC","batch_id","is_new"
        ])
    }


# ---------------- UTILITIES ----------------

def decode_mime_words(s):
    if not s:
        return ""
    decoded = ""
    for word, enc in decode_header(s):
        if isinstance(word, bytes):
            decoded += word.decode(enc or "utf-8", errors="ignore")
        else:
            decoded += word
    return decoded.strip()


def extract_domain_from_address(address):
    if not address:
        return "-"
    m = re.search(r'@([\w\.-]+)', address)
    return m.group(1).lower() if m else "-"


def extract_auth_results_from_headers(msg):
    auth = msg.get("Authentication-Results","")
    spf=dkim=dmarc="neutral"

    m=re.search(r"spf=(\w+)",auth,re.I)
    if m: spf=m.group(1).lower()

    m=re.search(r"dkim=(\w+)",auth,re.I)
    if m: dkim=m.group(1).lower()

    m=re.search(r"dmarc=(\w+)",auth,re.I)
    if m: dmarc=m.group(1).lower()

    return spf,dkim,dmarc


def format_date_to_ist_string(raw_date):
    if not raw_date:
        return "-",None

    try:
        dt=parsedate_to_datetime(raw_date)
    except:
        return raw_date,None

    if dt.tzinfo is None:
        dt=dt.replace(tzinfo=datetime.timezone.utc)

    ist=pytz.timezone("Asia/Kolkata")
    dt_ist=dt.astimezone(ist)
    naive=dt_ist.replace(tzinfo=None)

    return dt_ist.strftime("%d-%b-%Y %I:%M %p"), naive


# ---------------- FAST FETCH ----------------

def fetch_inbox_emails_single(email_addr,password,last_uid):

    results=[]
    new_last_uid=last_uid

    try:
        imap=imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_addr,password)
        imap.select("inbox")

        status,data=imap.status("INBOX","(UIDNEXT)")
        uidnext=None

        if status=="OK":
            m=re.search(r'UIDNEXT (\d+)',data[0].decode())
            if m:
                uidnext=int(m.group(1))

        uids=[]

        if last_uid and uidnext:

            start=int(last_uid)+1
            end=uidnext-1

            if start<=end:

                status,data=imap.uid("search",None,f"UID {start}:{end}")

                if status=="OK" and data and data[0]:
                    uids=data[0].split()

        else:

            status,data=imap.uid("search",None,"ALL")

            if status=="OK" and data and data[0]:
                all_uids=data[0].split()
                uids=all_uids[-100:]


        for uid in uids:

            uid_str=uid.decode()

            res,msg_data=imap.uid("fetch",uid_str,"(BODY.PEEK[HEADER])")

            if res!="OK":
                continue

            msg=email.message_from_bytes(msg_data[0][1])

            subject=decode_mime_words(msg.get("Subject","No Subject"))
            from_h=decode_mime_words(msg.get("From","-"))

            domain=extract_domain_from_address(from_h)

            spf,dkim,dmarc=extract_auth_results_from_headers(msg)

            raw_date=msg.get("Date","")

            formatted,dt=format_date_to_ist_string(raw_date)

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

            if new_last_uid is None or int(uid_str)>int(new_last_uid):
                new_last_uid=uid_str

        imap.logout()

    except Exception as e:
        return email_addr, pd.DataFrame(), last_uid, str(e)

    df=pd.DataFrame(results)

    return email_addr, df, new_last_uid, None


# ---------------- PARALLEL FETCH ----------------

def process_fetch():

    st.session_state.fetch_batch_id+=1
    batch=st.session_state.fetch_batch_id

    futures=[]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        for _,r in st.session_state.creds_df.iterrows():

            email_addr=r.get("Email","").strip()
            pwd=r.get("Password","").strip()

            if not email_addr or not pwd:
                continue

            if email_addr not in st.session_state.mailbox_data:
                st.session_state.mailbox_data[email_addr]=get_empty_mailbox_structure()

            mailbox=st.session_state.mailbox_data[email_addr]

            futures.append(
                executor.submit(
                    fetch_inbox_emails_single,
                    email_addr,
                    pwd,
                    mailbox["last_uid"]
                )
            )

        for f in as_completed(futures):

            email_addr,df_new,new_uid,err=f.result()

            if err:
                st.error(f"{email_addr}: {err}")
                continue

            mailbox=st.session_state.mailbox_data[email_addr]

            if not df_new.empty:

                df_new["batch_id"]=batch
                df_new["is_new"]=True

                mailbox["df"]=pd.concat([mailbox["df"],df_new],ignore_index=True)

                mailbox["df"]=mailbox["df"].drop_duplicates(subset=["UID"],keep="last")

                mailbox["df"]["is_new"]=mailbox["df"]["batch_id"]==batch

                mailbox["last_uid"]=new_uid


# ---------------- UI ----------------

st.markdown("### 📋 Account Credentials")

column_config={
    "Email":st.column_config.TextColumn("Email"),
    "Password":st.column_config.TextColumn("App Password")
}

edited_df=st.data_editor(
    st.session_state.creds_df,
    num_rows="dynamic",
    column_config=column_config,
    use_container_width=True,
    hide_index=True
)

st.session_state.creds_df=edited_df


st.markdown("---")

col1,col2=st.columns(2)

with col1:

    if st.button("🔄 Fetch New (Fast Parallel)"):

        process_fetch()

        st.success("Fetch completed.")


with col2:

    if st.button("🗑 Clear All"):

        st.session_state.mailbox_data={}
        st.rerun()


# ---------------- DISPLAY ----------------

st.markdown("### 📊 Email Counts")

if not st.session_state.mailbox_data:

    st.info("No emails fetched yet")

else:

    cols=st.columns(len(st.session_state.mailbox_data))

    for i,(em,data) in enumerate(st.session_state.mailbox_data.items()):

        total=len(data["df"])
        newc=int(data["df"]["is_new"].sum())

        cols[i].metric(em.split("@")[0],total,f"{newc} new")


st.markdown("---")


# ---------------- TABLE ----------------

rows=[]

for em,data in st.session_state.mailbox_data.items():

    df=data["df"]

    for _,r in df.iterrows():

        rows.append({
            "Account":em.split("@")[0],
            "Domain":r["Domain"],
            "From":r["From"],
            "Subject":r["Subject"],
            "Time":r["Date"],
            "SPF":r["SPF"],
            "DKIM":r["DKIM"],
            "DMARC":r["DMARC"],
            "is_new":r["is_new"]
        })

if rows:

    df=pd.DataFrame(rows)

    def highlight(row):
        if row["is_new"]:
            return ["background-color:#90EE90"]*len(row)
        return [""]*len(row)

    st.dataframe(
        df.style.apply(highlight,axis=1),
        use_container_width=True,
        hide_index=True
    )
