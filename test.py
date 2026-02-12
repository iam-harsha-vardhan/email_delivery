import streamlit as st
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
import datetime
import re
import pandas as pd
import base64

# --- Page Setup ---
st.set_page_config(page_title="Email Auth Checker", layout="wide")
st.title("📧 Email Authentication Report (SPF/DKIM/DMARC)")

# Added FROM column
DF_COLS = [
    "Subject", "Date", "From",
    "SPF", "DKIM", "DMARC",
    "Domain", "Type", "Sub ID",
    "Message-ID", "Mailbox", "Batch_ID"
]

# --- Session state setup ---
if 'df' not in st.session_state:
    st.session_state.df = pd.DataFrame(columns=DF_COLS)
if 'last_uid' not in st.session_state:
    st.session_state.last_uid = None
if 'spam_df' not in st.session_state:
    st.session_state.spam_df = pd.DataFrame(columns=DF_COLS)
if 'email_input' not in st.session_state:
    st.session_state.email_input = ""
if 'password_input' not in st.session_state:
    st.session_state.password_input = ""
if 'batch_counter' not in st.session_state:
    st.session_state.batch_counter = 0

today = datetime.date.today()
if 'fetch_dates' not in st.session_state or st.session_state.fetch_dates is None:
    st.session_state.fetch_dates = (today, today)

# --- Input UI ---
with st.container():
    col1, col2, col3, col4 = st.columns([3,3,2,1])
    with col1:
        email_input = st.text_input("📧 Gmail Address", key="email_box")
    with col2:
        password_input = st.text_input("🔐 App Password", type="password", key="pwd_box")
    with col3:
        date_range = st.date_input("Select Date Range",
            value=st.session_state.fetch_dates,
            max_value=today,
            key="date_box"
        )
        if isinstance(date_range, tuple) and len(date_range)==2:
            s,e=date_range
            if s>e: s,e=e,s
            st.session_state.fetch_dates=(s,e)
        elif isinstance(date_range, datetime.date):
            st.session_state.fetch_dates=(date_range,date_range)
        else:
            st.session_state.fetch_dates=(today,today)
    with col4:
        st.markdown("####")
        if st.button("🔁"):
            for key in list(st.session_state.keys()):
                if key not in ['date_box','fetch_dates']:
                    del st.session_state[key]
            st.rerun()

st.session_state.email_input=email_input
st.session_state.password_input=password_input

if not email_input or not password_input:
    st.warning("Enter Gmail + App Password")
    st.stop()

START_DATE, END_DATE = st.session_state.fetch_dates
IS_DEFAULT_TODAY = START_DATE==today and END_DATE==today
IS_SINGLE_DAY = START_DATE==END_DATE

# ---------- UTILITIES ----------

def decode_mime_words(s):
    if not s: return ""
    out=""
    for part,enc in decode_header(s):
        try:
            if isinstance(part,bytes):
                out+=part.decode(enc or 'utf-8',errors='ignore')
            else:
                out+=part
        except:
            out+=part.decode('utf-8','ignore') if isinstance(part,bytes) else str(part)
    return out.strip()

def format_date_ist(date_str):
    if not date_str: return "-"
    try:
        dt=parsedate_to_datetime(date_str)
        ist=datetime.timezone(datetime.timedelta(hours=5,minutes=30))
        return dt.astimezone(ist).strftime("%d-%b-%Y %I:%M %p")
    except:
        return str(date_str)

def extract_id_details(search_string,data):
    m=re.search(r'(GTC-[^@_]+|GMFP-[^@_]+|GRM-[^@_]+|GRTC-[^@_]+)',search_string,re.I)
    if m:
        sid=m.group(1)
        data["Sub ID"]=sid
        l=sid.lower()
        if 'grm' in l: data["Type"]='FPR'
        elif 'gmfp' in l: data["Type"]='FP'
        elif 'gtc' in l: data["Type"]='FPTC'
        elif 'grtc' in l: data["Type"]='FPRTC'
        return True
    return False

def parse_email_message(msg,batch_id):
    raw_date=msg.get("Date","")
    data={
        "Subject":decode_mime_words(msg.get("Subject","No Subject")),
        "Date":format_date_ist(raw_date),
        "From":decode_mime_words(msg.get("From","")),
        "SPF":"-","DKIM":"-","DMARC":"-","Domain":"-",
        "Type":"-","Sub ID":"-",
        "Message-ID":decode_mime_words(msg.get("Message-ID","")),
        "Batch_ID":batch_id
    }

    headers_str=''.join(f"{h}: {v}\n" for h,v in msg.items())

    m=re.search(r'Authentication-Results:.*?smtp.mailfrom=([\w\.-]+)',headers_str,re.I)
    if m:
        data["Domain"]=m.group(1).lower()
    else:
        f=data["From"]
        m=re.search(r'<(?:.+@)?([\w\.-]+)>|@([\w\.-]+)$',f)
        if m:
            data["Domain"]=(m.group(1) or m.group(2)).lower()

    for key in ["spf","dkim","dmarc"]:
        m=re.search(fr'{key}=(\w+)',headers_str,re.I)
        if m: data[key.upper()]=m.group(1).lower()

    if not extract_id_details(headers_str,data):
        for h,v in msg.items():
            if not v: continue
            for part in str(v).split('_'):
                if len(part)<20: continue
                try:
                    dec=base64.b64decode(part+'='*(-len(part)%4)).decode('utf-8','ignore')
                    if extract_id_details(dec,data): break
                except: pass
            if data["Type"]!="-": break
    return data

def fetch_emails(start_date,end_date,mailbox="inbox",use_uid_since=False,last_uid=None,current_batch_id=0):
    results=[]
    s=start_date.strftime("%d-%b-%Y")
    e=(end_date+datetime.timedelta(days=1)).strftime("%d-%b-%Y")
    new_last=last_uid
    try:
        imap=imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(st.session_state.email_input,st.session_state.password_input)
        imap.select(mailbox)
        if mailbox=="inbox" and use_uid_since and last_uid:
            criteria=f'(UID {int(last_uid)+1}:* SINCE {s} BEFORE {e})'
        else:
            criteria=f'(SINCE {s} BEFORE {e})'
        status,data=imap.uid('search',None,criteria)
        uids=data[0].split()
        for uid in uids:
            _,msg_data=imap.uid('fetch',uid,'(BODY.PEEK[HEADER])')
            for part in msg_data:
                if isinstance(part,tuple):
                    msg=email.message_from_bytes(part[1])
                    d=parse_email_message(msg,current_batch_id)
                    d["Mailbox"]="Inbox" if mailbox=="inbox" else "Spam"
                    results.append(d)
            if mailbox=="inbox":
                new_last=max(new_last,uid.decode()) if new_last else uid.decode()
        imap.logout()
    except Exception as e:
        st.error(str(e))
    return pd.DataFrame(results,columns=DF_COLS), new_last

def process_fetch_results(new_df,new_uid,target_df):
    if not target_df.empty:
        seen=set(target_df["Message-ID"].dropna())
        new_df=new_df[~new_df["Message-ID"].isin(seen)]
    if not new_df.empty:
        combined=pd.concat([new_df,target_df],ignore_index=True)
        combined=combined.sort_values(by='Batch_ID',ascending=False,ignore_index=True)
        return combined,len(new_df),new_uid
    return target_df,0,new_uid

# ---------- FETCH BUTTON ----------
if st.button("📥 Fetch Emails"):
    st.session_state.batch_counter+=1
    b=st.session_state.batch_counter
    use_uid=not st.session_state.df.empty and st.session_state.last_uid is not None
    with st.spinner("Fetching..."):
        inbox,new_uid=fetch_emails(START_DATE,END_DATE,"inbox",use_uid,st.session_state.last_uid,b)
        spam,_=fetch_emails(START_DATE,END_DATE,"[Gmail]/Spam",False,None,b)
        df_new=pd.concat([inbox,spam],ignore_index=True)
        st.session_state.df,count,st.session_state.last_uid=process_fetch_results(df_new,new_uid,st.session_state.df)
        st.success(f"Fetched {count} emails")

# ---------- MAIN TABLE ----------
st.subheader("📬 Processed Emails")
if not st.session_state.df.empty:
    inbox_cols=["Subject","From","Date","Domain","SPF","DKIM","DMARC","Type","Mailbox","Batch_ID"]
    display_df=st.session_state.df.reindex(columns=inbox_cols,fill_value="-")
    display_df.index=display_df.index+1
    st.dataframe(display_df,use_container_width=True,column_config={"Batch_ID":None})

# ---------- FAILED AUTH ----------
if not st.session_state.df.empty:
    failed=st.session_state.df[
        (st.session_state.df["SPF"]!="pass")|
        (st.session_state.df["DKIM"]!="pass")|
        (st.session_state.df["DMARC"]!="pass")
    ]
    if not failed.empty:
        st.subheader("❌ Failed Auth Emails")
        failed_cols=["Subject","From","Date","Domain","SPF","DKIM","DMARC","Type","Sub ID","Mailbox"]
        failed_display=failed[failed_cols].copy()
        failed_display.index=failed_display.index+1
        st.dataframe(failed_display,use_container_width=True)
    else:
        st.success("All emails passed authentication")

# ---------- SPAM ----------
if not st.session_state.spam_df.empty:
    st.subheader("🚫 Spam Folder Emails")
    spam_cols=["Subject","From","Date","Domain","Type","Mailbox","Batch_ID"]
    display_spam=st.session_state.spam_df.reindex(columns=spam_cols,fill_value="-")
    display_spam.index=display_spam.index+1
    st.dataframe(display_spam,use_container_width=True,column_config={"Batch_ID":None})
