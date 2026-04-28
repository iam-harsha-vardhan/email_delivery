import streamlit as st
import imaplib, email, datetime, re, base64, concurrent.futures
import pandas as pd
from email.header import decode_header
from email.utils import parsedate_to_datetime

st.set_page_config(page_title='Enterprise Email Auth Checker', layout='wide')
st.title('📧 Enterprise Email Authentication Checker')

DF_COLS=["Subject","Date","Domain","SPF","DKIM","DMARC","Type","Sub ID","Mailbox","Message-ID","Batch_ID"]
ID_RE=re.compile(r'(GRM-[A-Za-z0-9._-]+|GMFP-[A-Za-z0-9._-]+|GTC-[A-Za-z0-9._-]+|GRTC-[A-Za-z0-9._-]+)',re.I)

for k,v in {
 'df':pd.DataFrame(columns=DF_COLS),
 'spam_df':pd.DataFrame(columns=DF_COLS),
 'last_uid':None,
 'batch_counter':0,
 'fetch_dates':(datetime.date.today(),datetime.date.today())
}.items():
    if k not in st.session_state: st.session_state[k]=v

def decode_mime_words(s):
    if not s: return ''
    out=''
    for part,enc in decode_header(s):
        try:
            out += part.decode(enc or 'utf-8',errors='ignore') if isinstance(part,bytes) else str(part)
        except:
            pass
    return out.strip()

def format_date_ist(raw):
    try:
        dt=parsedate_to_datetime(raw)
        ist=datetime.timezone(datetime.timedelta(hours=5,minutes=30))
        return dt.astimezone(ist).strftime('%d-%b-%Y %I:%M %p')
    except:
        return raw or '-'

def get_type(s):
    x=s.lower()
    if x.startswith('grm'): return 'FPR'
    if x.startswith('gmfp'): return 'FP'
    if x.startswith('gtc'): return 'FPTC'
    if x.startswith('grtc'): return 'FPRTC'
    return '-'

def safe_b64(token):
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            pad=token+'='*(-len(token)%4)
            return fn(pad).decode('utf-8',errors='ignore')
        except:
            pass
    return ''

def extract_subid(text):
    if not text: return '-', '-'
    m=ID_RE.search(text)
    if m:
        sid=m.group(1); return sid,get_type(sid)
    for t in re.split(r'[\s<>()@._:;,\[\]{}]+',text):
        if len(t)<6: continue
        d=safe_b64(t)
        if d:
            m=ID_RE.search(d)
            if m:
                sid=m.group(1); return sid,get_type(sid)
    return '-', '-'

def extract_domain(msg, headers):
    # 1. Authentication-Results → smtp.mailfrom
    m = re.search(
        r'smtp\.mailfrom=[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        headers,
        re.I
    )
    if m:
        return m.group(1).lower()

    # 2. Return-Path fallback
    rp = msg.get('Return-Path', '')
    m = re.search(
        r'[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        rp,
        re.I
    )
    if m:
        return m.group(1).lower()

    # 3. From header fallback
    frm = decode_mime_words(msg.get('From', ''))
    m = re.search(
        r'[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        frm,
        re.I
    )
    if m:
        return m.group(1).lower()

    return '-'

def parse_email(msg,batch):
    headers=''.join(f'{k}: {v}\n' for k,v in msg.items())
    sid,typ=extract_subid(headers)
    data={
      'Subject':decode_mime_words(msg.get('Subject','No Subject')),
      'Date':format_date_ist(msg.get('Date','')),
      'Domain':extract_domain(msg,headers),
      'SPF':'-','DKIM':'-','DMARC':'-',
      'Type':typ,'Sub ID':sid,
      'Mailbox':'-','Message-ID':decode_mime_words(msg.get('Message-ID','')),
      'Batch_ID':batch
    }
    for key in ('SPF','DKIM','DMARC'):
        m=re.search(fr'{key.lower()}=(\w+)',headers,re.I)
        if m: data[key]=m.group(1).lower()
    return data

def fetch_box(user,pwd,mailbox,s,e,use_uid,last_uid,batch):
    rows=[]; new_last=last_uid
    imap=imaplib.IMAP4_SSL('imap.gmail.com')
    imap.login(user,pwd)
    imap.select(mailbox)
    ss=s.strftime('%d-%b-%Y'); ee=(e+datetime.timedelta(days=1)).strftime('%d-%b-%Y')
    crit=f'(SINCE {ss} BEFORE {ee})'
    if mailbox=='inbox' and use_uid and last_uid:
        crit=f'(UID {int(last_uid)+1}:* SINCE {ss} BEFORE {ee})'
    _,data=imap.uid('search',None,crit)
    for uid in data[0].split():
        uid_s=uid.decode()
        _,msgd=imap.uid('fetch',uid,'(BODY.PEEK[HEADER])')
        for part in msgd:
            if isinstance(part,tuple):
                msg=email.message_from_bytes(part[1])
                r=parse_email(msg,batch)
                r['Mailbox']='Inbox' if mailbox=='inbox' else 'Spam'
                rows.append(r)
        if mailbox=='inbox': new_last=uid_s if not new_last else str(max(int(new_last),int(uid_s)))
    imap.logout()
    return pd.DataFrame(rows,columns=DF_COLS),new_last

def merge_df(new,old):
    if old.empty: return new
    seen=set(old['Message-ID'].dropna())
    new=new[~new['Message-ID'].isin(seen)]
    out=pd.concat([new,old],ignore_index=True)
    return out.sort_values('Batch_ID',ascending=False,ignore_index=True)

def style_rows(row):
    fail=row['SPF']!='pass' or row['DKIM']!='pass' or row['DMARC']!='pass'
    return ['background-color: rgba(255,0,0,0.18)']*len(row) if fail else ['']*len(row)

c1,c2,c3,c4=st.columns([3,3,2,1])
with c1: user=st.text_input('📧 Gmail Address')
with c2: pwd=st.text_input('🔐 App Password',type='password')
with c3:
    dr=st.date_input('Select Date Range',value=st.session_state.fetch_dates,max_value=datetime.date.today())
    if isinstance(dr,tuple): st.session_state.fetch_dates=dr
    else: st.session_state.fetch_dates=(dr,dr)
with c4:
    st.markdown('###')
    if st.button('🔁 Clear'):
        st.session_state.clear(); st.rerun()

if not user or not pwd:
    st.warning('Enter Gmail + App Password')
    st.stop()

start,end=st.session_state.fetch_dates
b1,b2=st.columns(2)
with b1:
    if st.button('📥 Fetch Emails'):
        st.session_state.batch_counter+=1
        batch=st.session_state.batch_counter
        use_uid=not st.session_state.df.empty and st.session_state.last_uid is not None
        with st.spinner('Fetching Inbox + Spam...'):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
                f1=ex.submit(fetch_box,user,pwd,'inbox',start,end,use_uid,st.session_state.last_uid,batch)
                f2=ex.submit(fetch_box,user,pwd,'[Gmail]/Spam',start,end,False,None,batch)
                inbox,new_uid=f1.result(); spam,_=f2.result()
            st.session_state.df=merge_df(pd.concat([inbox,spam],ignore_index=True),st.session_state.df)
            st.session_state.last_uid=new_uid
with b2:
    if st.button('🗑️ Fetch Spam Only'):
        st.session_state.batch_counter+=1
        batch=st.session_state.batch_counter
        spam,_=fetch_box(user,pwd,'[Gmail]/Spam',start,end,False,None,batch)
        st.session_state.spam_df=merge_df(spam,st.session_state.spam_df)

st.subheader('📬 Processed Emails')
if not st.session_state.df.empty:
    cols=['Subject','Date','Domain','SPF','DKIM','DMARC','Type','Sub ID','Mailbox','Batch_ID']
    st.dataframe(st.session_state.df[cols].style.apply(style_rows,axis=1),use_container_width=True,column_config={'Batch_ID':None,'Sub ID':None})

failed=st.session_state.df[(st.session_state.df['SPF']!='pass')|(st.session_state.df['DKIM']!='pass')|(st.session_state.df['DMARC']!='pass')].reset_index(drop=True)
if not failed.empty:
    st.subheader('❌ Failed Auth Emails')
    st.dataframe(failed[['Subject','Domain','SPF','DKIM','DMARC','Type','Sub ID','Mailbox']].style.apply(style_rows,axis=1),use_container_width=True)
    st.info(f'Total Failed Rows: {len(failed)}')

if not st.session_state.spam_df.empty:
    st.subheader('🚫 Spam Emails')
    st.dataframe(st.session_state.spam_df[['Subject','Date','Domain','Type','Sub ID','Mailbox','Batch_ID']],use_container_width=True,column_config={'Batch_ID':None})
