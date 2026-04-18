# app.py

import streamlit as st
import dns.resolver
import socket
import ipaddress
import pandas as pd
import re

# ---------------------------------------------------
# Page Config
# ---------------------------------------------------

st.set_page_config(
    page_title="Email Preflight Checker",
    page_icon="📩",
    layout="wide"
)

# ---------------------------------------------------
# Custom CSS
# ---------------------------------------------------

st.markdown("""
<style>
.main {
    padding-top: 20px;
}
div[data-testid="metric-container"] {
    background: #111827;
    border: 1px solid #374151;
    padding: 15px;
    border-radius: 14px;
}
.stButton button {
    width: 100%;
    border-radius: 12px;
    height: 48px;
    font-size: 16px;
    font-weight: 600;
}
textarea, input {
    border-radius: 10px !important;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------
# DNS Helpers
# ---------------------------------------------------

def get_txt_records(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        output = []
        for r in answers:
            try:
                output.append(b"".join(r.strings).decode())
            except:
                output.append(str(r))
        return output
    except:
        return []


def get_spf_record(domain):
    txts = get_txt_records(domain)
    for item in txts:
        if item.lower().startswith("v=spf1"):
            return item
    return None


def ip_in_spf(ip, spf_record):
    if not spf_record:
        return False

    parts = spf_record.split()

    for p in parts:

        if p.startswith("ip4:"):
            block = p.replace("ip4:", "").strip()

            try:
                if "/" in block:
                    network = ipaddress.ip_network(block, strict=False)
                    if ipaddress.ip_address(ip) in network:
                        return True
                else:
                    if ip == block:
                        return True
            except:
                pass

    return False


def get_dmarc_record(domain):
    try:
        txts = get_txt_records(f"_dmarc.{domain}")
        for item in txts:
            if item.lower().startswith("v=dmarc1"):
                return item
        return None
    except:
        return None


def dkim_selector_exists(selector, domain):
    try:
        host = f"{selector}._domainkey.{domain}"
        txts = get_txt_records(host)

        for item in txts:
            if "p=" in item:
                return True

        return False
    except:
        return False


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None


def fcrdns_check(ip):
    ptr = reverse_dns(ip)

    if not ptr:
        return False, None

    try:
        ips = socket.gethostbyname_ex(ptr)[2]
        if ip in ips:
            return True, ptr
        return False, ptr
    except:
        return False, ptr


# ---------------------------------------------------
# Utilities
# ---------------------------------------------------

def parse_domain(value):
    if "@" in value:
        return value.split("@")[-1].strip()
    return value.strip()


def base_domain(domain):
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


# ---------------------------------------------------
# UI
# ---------------------------------------------------

st.title("📩 Email Preflight Checker")
st.caption("Validate SPF, DKIM, DMARC and FCrDNS for outbound IPs before first hit.")

# ---------------------------------------------------
# Checkboxes
# ---------------------------------------------------

st.subheader("Select Checks")

c1, c2, c3, c4 = st.columns(4)

with c1:
    check_spf = st.checkbox("SPF", value=True)

with c2:
    check_dkim = st.checkbox("DKIM", value=True)

with c3:
    check_dmarc = st.checkbox("DMARC", value=True)

with c4:
    check_fcrdns = st.checkbox("FCrDNS", value=True)

st.divider()

# ---------------------------------------------------
# Inputs
# ---------------------------------------------------

left, right = st.columns(2)

with left:
    domain = st.text_input("Main Domain", "loanpathwaynow.com")
    selector = st.text_input("DKIM Selector", "pat084")
    from_email = st.text_input("From Email", "insights@loanpathwaynow.com")

with right:
    return_path = st.text_input("Return Path", "insights@loanpathwaynow.com")
    ips_raw = st.text_area(
        "Outbound IPs (comma or new line separated)",
        "194.34.237.62\n194.34.237.63",
        height=140
    )

run = st.button("🚀 Run Preflight Check")

# ---------------------------------------------------
# Run Logic
# ---------------------------------------------------

if run:

    ip_list = re.split(r"[,\n]+", ips_raw)
    ip_list = [x.strip() for x in ip_list if x.strip()]

    rows = []

    # fetch once
    spf_record = get_spf_record(domain) if check_spf else None
    dkim_ready = dkim_selector_exists(selector, domain) if check_dkim else None
    dmarc_record = get_dmarc_record(domain) if check_dmarc else None

    from_domain = parse_domain(from_email)
    rp_domain = parse_domain(return_path)

    for ip in ip_list:

        row = {"IP": ip}

        # SPF
        if check_spf:
            if ip_in_spf(ip, spf_record):
                row["SPF"] = f"PASS with IP {ip}"
            else:
                row["SPF"] = "FAIL"

        # DKIM
        if check_dkim:
            if dkim_ready:
                row["DKIM"] = f"PASS with domain {domain}"
            else:
                row["DKIM"] = "FAIL"

        # DMARC
        if check_dmarc:

            aligned = (
                base_domain(from_domain) == base_domain(domain)
                or base_domain(rp_domain) == base_domain(domain)
            )

            if dmarc_record and aligned:
                row["DMARC"] = "PASS"
            else:
                row["DMARC"] = "FAIL"

        # FCrDNS
        if check_fcrdns:
            ok, ptr = fcrdns_check(ip)

            row["FCrDNS"] = "PASS" if ok else "FAIL"
            row["PTR Hostname"] = ptr if ptr else "No PTR"

        rows.append(row)

    df = pd.DataFrame(rows)

    # ---------------------------------------------------
    # Summary
    # ---------------------------------------------------

    st.subheader("📊 Summary")

    m1, m2, m3, m4 = st.columns(4)

    if check_spf:
        val = "PASS" if all("PASS" in x for x in df["SPF"]) else "FAIL"
        m1.metric("SPF", val)

    if check_dkim:
        val = "PASS" if all("PASS" in x for x in df["DKIM"]) else "FAIL"
        m2.metric("DKIM", val)

    if check_dmarc:
        val = "PASS" if all("PASS" in x for x in df["DMARC"]) else "FAIL"
        m3.metric("DMARC", val)

    if check_fcrdns:
        val = "PASS" if all("PASS" in x for x in df["FCrDNS"]) else "FAIL"
        m4.metric("FCrDNS", val)

    st.divider()

    # ---------------------------------------------------
    # Gmail Preview
    # ---------------------------------------------------

    st.subheader("📬 Gmail Show Original Preview")

    first = df.iloc[0]

    if check_spf:
        st.code(first["SPF"])

    if check_dkim:
        st.code(first["DKIM"])

    if check_dmarc:
        st.code("DMARC: " + first["DMARC"])

    st.divider()

    # ---------------------------------------------------
    # Detailed Results
    # ---------------------------------------------------

    st.subheader("📋 Detailed Results")
    st.dataframe(df, use_container_width=True)

    st.divider()

    # ---------------------------------------------------
    # Final Verdict
    # ---------------------------------------------------

    all_good = True

    if check_spf:
        all_good = all_good and all("PASS" in x for x in df["SPF"])

    if check_dkim:
        all_good = all_good and all("PASS" in x for x in df["DKIM"])

    if check_dmarc:
        all_good = all_good and all("PASS" in x for x in df["DMARC"])

    if check_fcrdns:
        all_good = all_good and all("PASS" in x for x in df["FCrDNS"])

    st.subheader("🚦 Launch Readiness")

    if all_good:
        st.success("✅ READY FOR FIRST HIT")
    else:
        st.error("❌ NOT READY FOR FIRST HIT")
