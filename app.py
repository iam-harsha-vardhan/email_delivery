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


# ---------- Basic page ----------

st.set_page_config(
    page_title="Dynamic Multi-Account Inbox Comparator",
    layout="wide"
)

st.title("📧 Dynamic Multi-Account Inbox Comparator")


# ---------- UI Styling ----------

st.markdown("""
<style>

.block-container{
    padding-top:1rem;
}

.stButton>button{
    border-radius:8px;
    height:42px;
    font-weight:600;
}

[data-testid="stMetric"]{
    background:#f8f9fb;
    padding:10px;
    border-radius:10px;
    border:1px solid #e6e8ef;
}

thead tr th{
    background:#f1f3f9 !important;
}

</style>
""", unsafe_allow_html=True)



# ---------- Configurable defaults ----------

UID_SCAN_LIMIT = 2000
CHUNK_SIZE = 200



# ---------- Session state ----------

if "creds_df" not in st.session_state:
    st.session_state.creds_df = pd.DataFrame([{
        "Email":"",
        "Password":""
    }])

if "mailbox_data" not in st.session_state:
    st.session_state.mailbox_data = {}

if "fetch_batch_id" not in st.session_state:
    st.session_state.fetch_batch_id = 0



# ---------- Mailbox structure ----------

def get_empty_mailbox_structure():

    return {
        "last_uid":None,

        "df":pd.DataFrame(columns=[

            "UID",
            "Domain",
            "Subject",
            "From",
            "Message-ID",
            "Date",
            "Date_dt",
            "Sub ID",
            "Type",
            "SPF",
            "DKIM",
            "DMARC",
            "batch_id",
            "is_new"
        ]),

        "uid_date_cache":{}
    }



# ---------- Utilities ----------

def decode_mime_words(s):

    if not s:
        return ""

    decoded=""

    for word,enc in decode_header(s):

        if isinstance(word,bytes):

            try:
                decoded+=word.decode(enc or "utf-8",errors="ignore")
            except:
                decoded+=word.decode("utf-8",errors="ignore")

        else:
            decoded+=word

    return decoded.strip()



def extract_domain_from_address(address):

    if not address:
        return "-"

    m=re.search(r'@([\w\.-]+)',address)

    return m.group(1).lower() if m else "-"



def extract_auth_results_from_headers(msg):

    auth=msg.get("Authentication-Results","") or " ".join(
        f"{h}: {v}" for h,v in msg.items()
    )

    spf=dkim=dmarc="neutral"

    m=re.search(r"spf=(\w+)",auth,re.I)
    if m:
        spf=m.group(1).lower()

    m=re.search(r"dkim=(\w+)",auth,re.I)
    if m:
        dkim=m.group(1).lower()

    m=re.search(r"dmarc=(\w+)",auth,re.I)
    if m:
        dmarc=m.group(1).lower()

    return spf,dkim,dmarc



# ---------- Sub-ID extraction ----------

ID_RE=re.compile(
    r'\b(GRM-[A-Za-z0-9\-]+|GMFP-[A-Za-z0-9\-]+|GTC-[A-Za-z0-9\-]+|GRTC-[A-Za-z0-9\-]+)\b',
    re.I
)


def map_id_to_type(sub_id):

    if not sub_id:
        return "-"

    lid=sub_id.lower()

    if lid.startswith("grm"):
        return "FPR"

    if lid.startswith("gmfp"):
        return "FP"

    if lid.startswith("gtc"):
        return "FPTC"

    if lid.startswith("grtc"):
        return "FPRTC"

    return "-"



def try_base64_variants(s):

    if not s or len(s)<4:
        return None

    s=s.strip()

    if s.startswith("<") and s.endswith(">"):
        s=s[1:-1]

    for decoder in (base64.b64decode,base64.urlsafe_b64decode):

        for pad in range(4):

            try:
                cand=s+("="*pad)

                decoded=decoder(cand)

                text=decoded.decode("utf-8",errors="ignore")

                if text.strip():
                    return text

            except:
                continue

    return None



def find_subid_in_text(txt):

    if not txt:
        return None

    m=ID_RE.search(txt)

    return m.group(1) if m else None



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

    formatted=dt_ist.strftime("%d-%b-%Y %I:%M %p")

    return formatted,naive
def extract_subid_from_msg(msg):

    msg_id_raw = decode_mime_words(
        msg.get("Message-ID","") or msg.get("Message-Id","") or ""
    )

    if msg_id_raw:

        tokens = re.split(r'[_\s]+', msg_id_raw)

        for t in tokens:

            maybe = find_subid_in_text(t)

            if maybe:
                return maybe, map_id_to_type(maybe)

            decoded = try_base64_variants(t)

            if decoded:

                m2 = find_subid_in_text(decoded)

                if m2:
                    return m2, map_id_to_type(m2)

    headers_str = " ".join(f"{h}:{v}" for h,v in msg.items())

    maybe = find_subid_in_text(headers_str)

    if maybe:
        return maybe, map_id_to_type(maybe)

    return None,"-"



# ---------- IMAP helper ----------

def parse_fetch_parts_for_uid_and_date(fetch_response_parts) -> List[tuple]:

    results = []

    for part in fetch_response_parts:

        if not isinstance(part,tuple):
            continue

        header_bytes, body_bytes = part

        meta = header_bytes.decode("utf-8","ignore")

        m = re.search(r'UID\s+(\d+)',meta)

        uid_str = m.group(1) if m else None

        raw_date=""

        if body_bytes:

            body = body_bytes.decode("utf-8","ignore")

            m = re.search(r'Date:\s*(.+)',body)

            if m:
                raw_date = m.group(1).strip()

        if uid_str:
            results.append((uid_str,raw_date))

    return results



# ---------- Fetch function ----------

def fetch_inbox_emails_single(
    email_addr,
    password,
    last_uid=None,
    fetch_n=None,
    fetch_unit='emails',
    uid_scan_limit=UID_SCAN_LIMIT,
    chunk_size=CHUNK_SIZE
):

    results=[]
    new_last_uid=last_uid

    try:

        imap = imaplib.IMAP4_SSL("imap.gmail.com")

        imap.login(email_addr,password)

        imap.select("inbox")

        if fetch_unit=="emails" and fetch_n:

            status,data=imap.uid("search",None,"ALL")

            if status=="OK" and data and data[0]:

                all_uids=data[0].split()

                uids=all_uids[-int(fetch_n):]

            else:
                uids=[]

        else:

            ist=pytz.timezone("Asia/Kolkata")

            now=datetime.datetime.now(ist).replace(tzinfo=None)

            if fetch_unit=="hours":

                cutoff=now-datetime.timedelta(hours=int(fetch_n))

            elif fetch_unit=="minutes":

                cutoff=now-datetime.timedelta(minutes=int(fetch_n))

            else:

                cutoff=now-datetime.timedelta(days=1)

            status,data=imap.uid("search",None,"ALL")

            all_uids=data[0].split()

            uids_to_check = all_uids[-uid_scan_limit:]

            matched=[]

            for uid in uids_to_check:

                uid_str=uid.decode()

                r,md=imap.uid("fetch",uid_str,"(BODY.PEEK[HEADER.FIELDS (DATE)])")

                parsed=parse_fetch_parts_for_uid_and_date(md)

                for u,d in parsed:

                    _,dt=format_date_to_ist_string(d)

                    if dt and dt>=cutoff:
                        matched.append(u.encode())

            uids=matched


        for uid in uids:

            uid_str=uid.decode()

            r,md=imap.uid("fetch",uid_str,"(BODY.PEEK[HEADER])")

            if r!="OK" or not md:
                continue

            msg=email.message_from_bytes(md[0][1])

            subject=decode_mime_words(msg.get("Subject","No Subject"))

            from_h=decode_mime_words(msg.get("From","-"))

            domain=extract_domain_from_address(from_h)

            spf,dkim,dmarc=extract_auth_results_from_headers(msg)

            sub_id,id_type=extract_subid_from_msg(msg)

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
                "Sub ID":sub_id or "-",
                "Type":id_type,
                "SPF":spf,
                "DKIM":dkim,
                "DMARC":dmarc
            })

            if new_last_uid is None or int(uid_str)>int(new_last_uid):

                new_last_uid=uid_str

        imap.logout()

    except Exception as e:

        st.error(f"{email_addr} : {e}")

        return pd.DataFrame(),last_uid


    return pd.DataFrame(results),new_last_uid



# ---------- Styling helpers ----------

def highlight_new_rows(row):

    return ['background-color:#d4f8d4']*len(row) if row.get("is_new",False) else ['']*len(row)



def highlight_presence_row(row):

    if str(row.get("Auth","")).lower()!="pass":

        return ['background-color:rgba(255,0,0,0.12)']*len(row)

    return highlight_new_rows(row)



# ---------- Credentials editor ----------

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



# ---------- Fetch controller ----------

def process_fetch(fetch_type,fetch_n=None,fetch_unit='emails'):

    any_run=False

    st.session_state.fetch_batch_id+=1
    current_batch=st.session_state.fetch_batch_id

    for _,r in st.session_state.creds_df.iterrows():

        email_addr=r.get("Email","").strip()
        pwd=r.get("Password","").strip()

        if not email_addr or not pwd:
            continue

        if email_addr not in st.session_state.mailbox_data:

            st.session_state.mailbox_data[email_addr]=get_empty_mailbox_structure()

        mailbox=st.session_state.mailbox_data[email_addr]

        any_run=True

        df_new,new_uid=fetch_inbox_emails_single(
            email_addr,
            pwd,
            last_uid=mailbox.get("last_uid"),
            fetch_n=fetch_n,
            fetch_unit=fetch_unit
        )

        if not df_new.empty:

            df_new["batch_id"]=current_batch
            df_new["is_new"]=True

            mailbox["df"]=pd.concat(
                [mailbox["df"],df_new],
                ignore_index=True
            ).drop_duplicates(subset=["UID"],keep="last")

            mailbox["df"]["is_new"]=mailbox["df"]["batch_id"]==current_batch

            try:
                mailbox["last_uid"]=str(mailbox["df"]["UID"].astype(int).max())
            except:
                pass

    return any_run
