# app.py
# HIGH-SPEED BULK EMAIL PREFLIGHT CHECKER
# Multi-threaded version for 3k+ rows
# SPF / DKIM / DMARC / FCrDNS

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
div[data-testid="metric-container"]{
background:#111827;
border:1px solid #374151;
padding:14px;
border-radius:14px;
}
.stButton button{
width:100%;
height:48px;
border-radius:12px;
font-weight:700;
}
</style>
""", unsafe_allow_html=True)

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
        return "FAIL", "No PTR", ""

    try:
        ips = socket.gethostbyname_ex(host)[2]

        if ip in ips:
            return "PASS", host, ",".join(ips)
        else:
            return "FAIL", host, ",".join(ips)

    except:
        return "FAIL", host, ""

def email_domain(v):
    if "@" in str(v):
        return v.split("@")[-1].strip().lower()
    return str(v).strip().lower()

def org_domain(v):
    parts = v.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return v

def split_ips(value):
    if pd.isna(value):
        return []

    vals = re.split(r"[,\n|]+", str(value))
    return [x.strip() for x in vals if x.strip()]

# ---------------------------------------------------
# CACHE
# ---------------------------------------------------

spf_cache = {}
dmarc_cache = {}
dkim_cache = {}

def cached_spf(domain):
    if domain not in spf_cache:
        spf_cache[domain] = get_spf(domain)
    return spf_cache[domain]

def cached_dmarc(domain):
    if domain not in dmarc_cache:
        dmarc_cache[domain] = get_dmarc(domain)
    return dmarc_cache[domain]

def cached_dkim(selector, domain):
    key = f"{selector}|{domain}"
    if key not in dkim_cache:
        dkim_cache[key] = dkim_exists(selector, domain)
    return dkim_cache[key]

# ---------------------------------------------------
# MAIN PROCESS FUNCTION
# ---------------------------------------------------

def process_row(data):

    domain = data["domain"]
    selector = data["selector"]
    from_email = data["from_email"]
    return_path = data["return_path"]
    ip = data["ip"]

    run_spf = data["run_spf"]
    run_dkim = data["run_dkim"]
    run_dmarc = data["run_dmarc"]
    run_fcrdns = data["run_fcrdns"]

    row = {
        "Domain": domain,
        "IP": ip
    }

    # SPF
    if run_spf:
        spf = cached_spf(domain)
        row["SPF"] = f"PASS with IP {ip}" if ip_in_spf(ip, spf) else "FAIL"

    # DKIM
    if run_dkim:
        ok = cached_dkim(selector, domain)
        row["DKIM"] = f"PASS with domain {domain}" if ok else "FAIL"

    # DMARC
    if run_dmarc:

        dmarc = cached_dmarc(domain)

        fd = email_domain(from_email)
        rp = email_domain(return_path)

        aligned = (
            org_domain(fd) == org_domain(domain)
            or org_domain(rp) == org_domain(domain)
        )

        row["DMARC"] = "PASS" if dmarc and aligned else "FAIL"

    # FCrDNS
    if run_fcrdns:
        status, host, fwd = fcrdns(ip)
        row["FCrDNS"] = status
        row["PTR Host"] = host
        row["Forward IPs"] = fwd

    return row

# ---------------------------------------------------
# UI
# ---------------------------------------------------

st.title("📩 High Speed Bulk Email Preflight Checker")

st.subheader("Select Checks")

c1, c2, c3, c4 = st.columns(4)

with c1:
    run_spf = st.checkbox("SPF", True)

with c2:
    run_dkim = st.checkbox("DKIM", True)

with c3:
    run_dmarc = st.checkbox("DMARC", True)

with c4:
    run_fcrdns = st.checkbox("FCrDNS", True)

st.divider()

st.subheader("Bulk CSV Upload")

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

workers = st.slider(
    "Threads",
    min_value=5,
    max_value=100,
    value=30
)

# ---------------------------------------------------
# RUN BULK
# ---------------------------------------------------

if file is not None:

    df = pd.read_csv(file)

    st.write("Preview")
    st.dataframe(df.head(20), use_container_width=True)

    if st.button("🚀 Run High Speed Bulk Check"):

        jobs = []

        for _, r in df.iterrows():

            domain = str(r.get("domain", "")).strip()
            selector = str(r.get("selector", "")).strip()
            from_email = str(r.get("from_email", "")).strip()
            return_path = str(r.get("return_path", "")).strip()

            ips = split_ips(r.get("ip", ""))

            for ip in ips:

                jobs.append({
                    "domain": domain,
                    "selector": selector,
                    "from_email": from_email,
                    "return_path": return_path,
                    "ip": ip,
                    "run_spf": run_spf,
                    "run_dkim": run_dkim,
                    "run_dmarc": run_dmarc,
                    "run_fcrdns": run_fcrdns
                })

        total = len(jobs)

        st.info(f"Total checks to run: {total}")

        progress = st.progress(0)

        results = []
        done = 0

        with ThreadPoolExecutor(max_workers=workers) as executor:

            futures = [executor.submit(process_row, job) for job in jobs]

            for future in as_completed(futures):
                results.append(future.result())
                done += 1
                progress.progress(done / total)

        out = pd.DataFrame(results)

        st.success("Completed")

        st.subheader("Results")
        st.dataframe(out, use_container_width=True)

        st.download_button(
            "📥 Download Results CSV",
            out.to_csv(index=False),
            file_name="preflight_results.csv",
            mime="text/csv"
        )
