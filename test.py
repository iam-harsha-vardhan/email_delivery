# app.py
# FINAL PRODUCTION VERSION
# Single Check + Bulk Upload
# 75 threads optimized for 3k–5k rows
# Same terminology labels everywhere

import streamlit as st
import pandas as pd
import dns.resolver
import socket
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------
# CONFIG
# ---------------------------------------------------

st.set_page_config(
    page_title="Email Preflight Checker",
    page_icon="📩",
    layout="wide"
)

# ---------------------------------------------------
# THREADS
# Ideal for local machine 3k–5k rows
# Change here if needed
# ---------------------------------------------------

DEFAULT_THREADS = 75

# ---------------------------------------------------
# CSS
# ---------------------------------------------------

st.markdown("""
<style>
.main {padding-top:15px;}
.stButton button{
width:100%;
height:46px;
border-radius:12px;
font-weight:700;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------
# DNS
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

def run_check(domain, return_path, from_domain,
              selector, display_from, ip):

    row = {
        "Domain": domain,
        "Return Path Address": return_path,
        "From Domain": from_domain,
        "DKIM Selector Id": selector,
        "Display From": display_from,
        "Ip Address": ip
    }

    # SPF
    spf = get_spf(domain)
    row["SPF"] = f"PASS with IP {ip}" if ip_in_spf(ip, spf) else "FAIL"

    # DKIM
    row["DKIM"] = f"PASS with domain {domain}" if dkim_exists(selector, domain) else "FAIL"

    # DMARC
    dmarc = get_dmarc(domain)
    row["DMARC"] = "PASS" if dmarc else "FAIL"

    # FCrDNS
    status, host = fcrdns(ip)
    row["FCrDNS"] = status
    row["PTR Host"] = host

    return row

# ---------------------------------------------------
# UI
# ---------------------------------------------------

st.title("📩 Email Preflight Checker")

tab1, tab2 = st.tabs(["Single Check", "Bulk Upload"])

# ===================================================
# SINGLE CHECK
# ===================================================

with tab1:

    st.subheader("Single Domain Check")

    c1, c2 = st.columns(2)

    with c1:
        domain = st.text_input("Domain")
        return_path = st.text_input("Return Path Address")
        from_domain = st.text_input("From Domain")

    with c2:
        selector = st.text_input("DKIM Selector Id")
        display_from = st.text_input("Display From")
        ip_raw = st.text_area("Ip Address (single / comma / newline / pipe)")

    if st.button("🚀 Run Single Check"):

        if not domain:
            st.warning("Domain required")
            st.stop()

        ips = split_ips(ip_raw)

        if not ips:
            st.warning("At least one IP required")
            st.stop()

        rows = []

        for ip in ips:
            rows.append(
                run_check(
                    domain,
                    return_path,
                    from_domain,
                    selector,
                    display_from,
                    ip
                )
            )

        df = pd.DataFrame(rows)

        st.subheader("Results")
        st.dataframe(df, use_container_width=True)

# ===================================================
# BULK CHECK
# ===================================================

with tab2:

    st.subheader("Bulk Upload CSV")

    sample = pd.DataFrame([
        {
            "Domain": "loanpathwaynow.com",
            "Return Path Address": "insights@loanpathwaynow.com",
            "From Domain": "loanpathwaynow.com",
            "DKIM Selector Id": "pat084",
            "Display From": "insights@loanpathwaynow.com",
            "Ip Address": "194.34.237.62,194.34.237.63"
        },
        {
            "Domain": "finshots.in",
            "Return Path Address": "bounce@mailer.finshots.in",
            "From Domain": "finshots.in",
            "DKIM Selector Id": "lgathoxm23wr275ega6lju2bgmuxkolm",
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

            jobs = []

            for _, r in df.iterrows():

                ips = split_ips(r.get("Ip Address", ""))

                for ip in ips:

                    jobs.append({
                        "Domain": str(r.get("Domain", "")).strip(),
                        "Return Path Address": str(r.get("Return Path Address", "")).strip(),
                        "From Domain": str(r.get("From Domain", "")).strip(),
                        "DKIM Selector Id": str(r.get("DKIM Selector Id", "")).strip(),
                        "Display From": str(r.get("Display From", "")).strip(),
                        "Ip Address": ip
                    })

            total = len(jobs)

            st.info(f"Running {total} checks with {DEFAULT_THREADS} threads")

            progress = st.progress(0)

            results = []
            done = 0

            with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:

                futures = [
                    executor.submit(
                        run_check,
                        j["Domain"],
                        j["Return Path Address"],
                        j["From Domain"],
                        j["DKIM Selector Id"],
                        j["Display From"],
                        j["Ip Address"]
                    )
                    for j in jobs
                ]

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
