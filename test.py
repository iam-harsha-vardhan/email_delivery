# app.py
# Bulk Email Preflight Checker
# SPF / DKIM / DMARC / FCrDNS
# Single + Bulk CSV Upload

import streamlit as st
import pandas as pd
import dns.resolver
import socket
import ipaddress
import re
from io import StringIO

# -------------------------------------------------
# PAGE
# -------------------------------------------------

st.set_page_config(
    page_title="Bulk Email Preflight Checker",
    page_icon="📩",
    layout="wide"
)

# -------------------------------------------------
# CSS
# -------------------------------------------------

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
height:46px;
border-radius:12px;
font-weight:700;
}
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------
# HELPERS
# -------------------------------------------------

def txt_records(name):
    try:
        ans = dns.resolver.resolve(name, "TXT")
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

# -------------------------------------------------
# PROCESS FUNCTION
# -------------------------------------------------

def process_row(domain, selector, from_email, return_path, ip,
                run_spf, run_dkim, run_dmarc, run_fcrdns):

    row = {
        "Domain": domain,
        "IP": ip
    }

    spf = get_spf(domain) if run_spf else None
    dmarc = get_dmarc(domain) if run_dmarc else None

    # SPF
    if run_spf:
        row["SPF"] = f"PASS with IP {ip}" if ip_in_spf(ip, spf) else "FAIL"

    # DKIM
    if run_dkim:
        row["DKIM"] = f"PASS with domain {domain}" if dkim_exists(selector, domain) else "FAIL"

    # DMARC
    if run_dmarc:
        fd = email_domain(from_email)
        rp = email_domain(return_path)

        aligned = (
            org_domain(fd) == org_domain(domain)
            or org_domain(rp) == org_domain(domain)
        )

        row["DMARC"] = "PASS" if dmarc and aligned else "FAIL"

    # FCrDNS
    if run_fcrdns:
        status, host, forward_ips = fcrdns(ip)
        row["FCrDNS"] = status
        row["PTR Host"] = host
        row["Forward IPs"] = forward_ips

    return row

# -------------------------------------------------
# UI
# -------------------------------------------------

st.title("📩 Bulk Email Preflight Checker")

tab1, tab2 = st.tabs(["Single Check", "Bulk Upload"])

# -------------------------------------------------
# CHECKBOXES
# -------------------------------------------------

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

# -------------------------------------------------
# SINGLE TAB
# -------------------------------------------------

with tab1:

    st.subheader("Single Validation")

    l, r = st.columns(2)

    with l:
        domain = st.text_input("Domain")
        selector = st.text_input("DKIM Selector")
        from_email = st.text_input("From Email")

    with r:
        return_path = st.text_input("Return Path")
        ips_raw = st.text_area("IPs (comma/new line)")

    if st.button("Run Single Check"):

        ips = [x.strip() for x in re.split(r"[,\n]+", ips_raw) if x.strip()]

        if not domain:
            st.warning("Domain required")
            st.stop()

        if not ips:
            st.warning("IP required")
            st.stop()

        rows = []

        for ip in ips:
            rows.append(
                process_row(
                    domain, selector, from_email,
                    return_path, ip,
                    run_spf, run_dkim,
                    run_dmarc, run_fcrdns
                )
            )

        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True)

# -------------------------------------------------
# BULK TAB
# -------------------------------------------------

with tab2:

    st.subheader("Bulk CSV Upload")

    sample = pd.DataFrame([
        {
            "domain": "loanpathwaynow.com",
            "selector": "pat084",
            "from_email": "insights@loanpathwaynow.com",
            "return_path": "insights@loanpathwaynow.com",
            "ip": "194.34.237.62"
        },
        {
            "domain": "finshots.in",
            "selector": "lgathoxm23wr275ega6lju2bgmuxkolm",
            "from_email": "morning@finshots.in",
            "return_path": "bounce@mailer.finshots.in",
            "ip": "24.110.92.9"
        }
    ])

    csv = sample.to_csv(index=False)

    st.download_button(
        "📥 Download Sample CSV",
        csv,
        file_name="sample_preflight.csv",
        mime="text/csv"
    )

    file = st.file_uploader("Upload CSV", type=["csv"])

    if file is not None:

        df_input = pd.read_csv(file)

        st.write("Preview:")
        st.dataframe(df_input, use_container_width=True)

        if st.button("Run Bulk Check"):

            output = []

            for _, r in df_input.iterrows():

                row = process_row(
                    str(r.get("domain", "")),
                    str(r.get("selector", "")),
                    str(r.get("from_email", "")),
                    str(r.get("return_path", "")),
                    str(r.get("ip", "")),
                    run_spf,
                    run_dkim,
                    run_dmarc,
                    run_fcrdns
                )

                output.append(row)

            result = pd.DataFrame(output)

            st.subheader("Results")
            st.dataframe(result, use_container_width=True)

            csv_out = result.to_csv(index=False)

            st.download_button(
                "📥 Download Results CSV",
                csv_out,
                file_name="preflight_results.csv",
                mime="text/csv"
            )
