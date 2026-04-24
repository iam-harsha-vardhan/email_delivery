# app.py
# FINAL ENTERPRISE VERSION
# ------------------------------------------------------------
# Supports:
# ✅ Single Entry Grid (can paste 1 row or many rows like Excel)
# ✅ Bulk CSV Upload
# ✅ Required Column Order:
#    Domain
#    Return Path Address
#    From Domain DKIM Selector Id
#    Display From
#    Ip Address
# ✅ Multi IPs in one cell (comma | newline | pipe)
# ✅ SPF / DKIM / DMARC / FCrDNS
# ✅ Multithreaded (ideal for 3k to 5k rows local)
# ------------------------------------------------------------

import streamlit as st
import pandas as pd
import dns.resolver
import socket
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------------------------------------------------------
# PAGE
# ------------------------------------------------------------

st.set_page_config(
    page_title="Email Preflight Checker",
    page_icon="📩",
    layout="wide"
)

# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------
# IDEAL DEFAULT FOR 3K - 5K LOCAL ROWS
# YOU CAN CHANGE THIS VALUE

DEFAULT_THREADS = 75

# ------------------------------------------------------------
# CSS
# ------------------------------------------------------------

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

# ------------------------------------------------------------
# DNS
# ------------------------------------------------------------

resolver = dns.resolver.Resolver()
resolver.timeout = 2
resolver.lifetime = 2

# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------

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
    vals = re.split(r"[,\n|]+", str(value))
    return [x.strip() for x in vals if x.strip()]

# ------------------------------------------------------------
# MAIN CHECK
# ------------------------------------------------------------

def process_row(job):

    domain = str(job["Domain"]).strip()
    return_path = str(job["Return Path Address"]).strip()
    selector = str(job["From Domain DKIM Selector Id"]).strip()
    from_email = str(job["Display From"]).strip()
    ip = str(job["Ip Address"]).strip()

    row = {
        "Domain": domain,
        "Ip Address": ip
    }

    # SPF
    spf = get_spf(domain)
    row["SPF"] = f"PASS with IP {ip}" if ip_in_spf(ip, spf) else "FAIL"

    # DKIM
    row["DKIM"] = f"PASS with domain {domain}" if dkim_exists(selector, domain) else "FAIL"

    # DMARC
    dmarc = get_dmarc(domain)

    fd = email_domain(from_email)
    rp = email_domain(return_path)

    aligned = (
        org_domain(fd) == org_domain(domain)
        or org_domain(rp) == org_domain(domain)
    )

    row["DMARC"] = "PASS" if dmarc and aligned else "FAIL"

    # FCrDNS
    status, host = fcrdns(ip)
    row["FCrDNS"] = status
    row["PTR Host"] = host

    return row

# ------------------------------------------------------------
# BULK ENGINE
# ------------------------------------------------------------

def run_jobs(df):

    jobs = []

    for _, r in df.iterrows():

        ips = split_ips(r["Ip Address"])

        for ip in ips:

            jobs.append({
                "Domain": r["Domain"],
                "Return Path Address": r["Return Path Address"],
                "From Domain DKIM Selector Id": r["From Domain DKIM Selector Id"],
                "Display From": r["Display From"],
                "Ip Address": ip
            })

    total = len(jobs)

    progress = st.progress(0)

    done = 0
    results = []

    with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:

        futures = [executor.submit(process_row, j) for j in jobs]

        for future in as_completed(futures):
            results.append(future.result())
            done += 1
            progress.progress(done / total)

    return pd.DataFrame(results)

# ------------------------------------------------------------
# UI
# ------------------------------------------------------------

st.title("📩 Email Preflight Checker")

tab1, tab2 = st.tabs(["Single / Excel Entry", "Bulk Upload"])

# ------------------------------------------------------------
# TAB 1
# ------------------------------------------------------------

with tab1:

    st.subheader("Single / Multi Row Entry")

    base = pd.DataFrame([
        {
            "Domain": "",
            "Return Path Address": "",
            "From Domain DKIM Selector Id": "",
            "Display From": "",
            "Ip Address": ""
        }
    ])

    edited = st.data_editor(
        base,
        num_rows="dynamic",
        use_container_width=True
    )

    if st.button("🚀 Run Grid Check"):

        df = pd.DataFrame(edited)

        df = df[
            df["Domain"].astype(str).str.strip() != ""
        ]

        if len(df) == 0:
            st.warning("Enter at least one row")
            st.stop()

        result = run_jobs(df)

        st.subheader("Results")
        st.dataframe(result, use_container_width=True)

        st.download_button(
            "📥 Download Results CSV",
            result.to_csv(index=False),
            file_name="results.csv",
            mime="text/csv"
        )

# ------------------------------------------------------------
# TAB 2
# ------------------------------------------------------------

with tab2:

    st.subheader("Bulk CSV Upload")

    sample = pd.DataFrame([
        {
            "Domain": "loanpathwaynow.com",
            "Return Path Address": "insights@loanpathwaynow.com",
            "From Domain DKIM Selector Id": "pat084",
            "Display From": "insights@loanpathwaynow.com",
            "Ip Address": "194.34.237.62,194.34.237.63"
        },
        {
            "Domain": "finshots.in",
            "Return Path Address": "bounce@mailer.finshots.in",
            "From Domain DKIM Selector Id": "lgathoxm23wr275ega6lju2bgmuxkolm",
            "Display From": "morning@finshots.in",
            "Ip Address": "24.110.92.9"
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

            result = run_jobs(df)

            st.subheader("Results")
            st.dataframe(result, use_container_width=True)

            st.download_button(
                "📥 Download Results CSV",
                result.to_csv(index=False),
                file_name="bulk_results.csv",
                mime="text/csv"
            )
