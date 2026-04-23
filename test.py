# app.py
# HIGH-SPEED BULK EMAIL PREFLIGHT CHECKER
# Optimized default threads for 3k to 5k rows on local machine

import streamlit as st
import pandas as pd
import dns.resolver
import socket
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------
# PAGE
# ---------------------------------------------------

st.set_page_config(
    page_title="High Speed Email Preflight Checker",
    page_icon="📩",
    layout="wide"
)

# ---------------------------------------------------
# CSS
# ---------------------------------------------------

st.markdown("""
<style>
.main {padding-top:15px;}
.stButton button{
width:100%;
height:48px;
border-radius:12px;
font-weight:700;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------
# DEFAULT THREADS
# ---------------------------------------------------
# IDEAL FOR LOCAL MACHINE 3K TO 5K RECORDS
# YOU CAN CHANGE THIS VALUE IF NEEDED

DEFAULT_THREADS = 75

# ---------------------------------------------------
# DNS RESOLVER
# ---------------------------------------------------

resolver = dns.resolver.Resolver()
resolver.timeout = 2
resolver.lifetime = 2

# ---------------------------------------------------
# HELPERS
# ---------------------------------------------------

def txt_records(name):
    try:
        ans = resolver.resolve(name, "TXT")
        out = []
        for r in ans:
            try:
                out.append(b"".join(r.strings).decode())
            except:
                out.append(str(r))
        return out
    except:
        return []

def get_spf(domain):
    for x in txt_records(domain):
        if x.lower().startswith("v=spf1"):
            return x
    return None

def get_dmarc(domain):
    for x in txt_records(f"_dmarc.{domain}"):
        if x.lower().startswith("v=dmarc1"):
            return x
    return None

def dkim_exists(selector, domain):
    if not selector:
        return False

    try:
        vals = txt_records(f"{selector}._domainkey.{domain}")
        return any("p=" in x for x in vals)
    except:
        return False

def ip_in_spf(ip, spf):
    if not spf:
        return False

    for token in spf.split():

        if token.startswith("ip4:"):
            val = token.replace("ip4:", "")

            try:
                if "/" in val:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(val, strict=False):
                        return True
                else:
                    if ip == val:
                        return True
            except:
                pass

    return False

def ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def fcrdns(ip):
    host = ptr(ip)

    if not host:
        return "FAIL", "No PTR"

    try:
        ips = socket.gethostbyname_ex(host)[2]

        if ip in ips:
            return "PASS", host
        else:
            return "FAIL", host

    except:
        return "FAIL", host

def split_ips(value):
    vals = re.split(r"[,\n|]+", str(value))
    return [x.strip() for x in vals if x.strip()]

# ---------------------------------------------------
# MAIN CHECK
# ---------------------------------------------------

def process_row(job):

    domain = job["domain"]
    selector = job["selector"]
    from_email = job["from_email"]
    return_path = job["return_path"]
    ip = job["ip"]

    row = {
        "Domain": domain,
        "IP": ip
    }

    spf = get_spf(domain)

    row["SPF"] = f"PASS with IP {ip}" if ip_in_spf(ip, spf) else "FAIL"

    row["DKIM"] = f"PASS with domain {domain}" if dkim_exists(selector, domain) else "FAIL"

    dmarc = get_dmarc(domain)
    row["DMARC"] = "PASS" if dmarc else "FAIL"

    status, host = fcrdns(ip)
    row["FCrDNS"] = status
    row["PTR Host"] = host

    return row

# ---------------------------------------------------
# UI
# ---------------------------------------------------

st.title("📩 High Speed Bulk Email Preflight Checker")

sample = pd.DataFrame([
    {
        "domain": "loanpathwaynow.com",
        "selector": "pat084",
        "from_email": "insights@loanpathwaynow.com",
        "return_path": "insights@loanpathwaynow.com",
        "ip": "194.34.237.62,194.34.237.63"
    }
])

st.download_button(
    "📥 Download Sample CSV",
    sample.to_csv(index=False),
    file_name="sample_preflight.csv",
    mime="text/csv"
)

file = st.file_uploader("Upload CSV", type=["csv"])

if file is not None:

    df = pd.read_csv(file)

    st.write("Preview")
    st.dataframe(df.head(20), use_container_width=True)

    if st.button("🚀 Run Bulk Check"):

        jobs = []

        for _, r in df.iterrows():

            ips = split_ips(r.get("ip", ""))

            for ip in ips:

                jobs.append({
                    "domain": str(r.get("domain", "")).strip(),
                    "selector": str(r.get("selector", "")).strip(),
                    "from_email": str(r.get("from_email", "")).strip(),
                    "return_path": str(r.get("return_path", "")).strip(),
                    "ip": ip
                })

        total = len(jobs)

        st.info(f"Running {total} checks with {DEFAULT_THREADS} threads")

        progress = st.progress(0)

        results = []
        done = 0

        with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:

            futures = [executor.submit(process_row, job) for job in jobs]

            for future in as_completed(futures):
                results.append(future.result())
                done += 1
                progress.progress(done / total)

        out = pd.DataFrame(results)

        st.success("Completed")

        st.dataframe(out, use_container_width=True)

        st.download_button(
            "📥 Download Results CSV",
            out.to_csv(index=False),
            file_name="results.csv",
            mime="text/csv"
        )
