# app.py

import streamlit as st
import dns.resolver
import socket
import ipaddress
import pandas as pd
import re

st.set_page_config(
    page_title="Email Preflight Checker",
    page_icon="📩",
    layout="wide"
)

# -------------------------
# Helpers
# -------------------------

def get_txt_records(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        records = []
        for r in answers:
            txt = b"".join(r.strings).decode()
            records.append(txt)
        return records
    except:
        return []


def get_spf_record(domain):
    txts = get_txt_records(domain)
    for record in txts:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def ip_authorized_in_spf(ip, spf_record):
    if not spf_record:
        return False

    parts = spf_record.split()

    for item in parts:
        if item.startswith("ip4:"):
            net = item.replace("ip4:", "").strip()
            try:
                if "/" in net:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False):
                        return True
                else:
                    if ip == net:
                        return True
            except:
                pass

    return False


def get_dmarc_record(domain):
    try:
        txts = get_txt_records(f"_dmarc.{domain}")
        for t in txts:
            if t.lower().startswith("v=dmarc1"):
                return t
        return None
    except:
        return None


def parse_domain(email_or_domain):
    if "@" in email_or_domain:
        return email_or_domain.split("@")[-1].strip()
    return email_or_domain.strip()


def get_base_domain(domain):
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def check_dkim_selector(selector, domain):
    try:
        host = f"{selector}._domainkey.{domain}"
        txts = get_txt_records(host)
        for t in txts:
            if "p=" in t:
                return True
        return False
    except:
        return False


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None


def forward_confirm(ip):
    host = reverse_dns(ip)

    if not host:
        return False, None

    try:
        ips = socket.gethostbyname_ex(host)[2]
        if ip in ips:
            return True, host
        return False, host
    except:
        return False, host


# -------------------------
# UI
# -------------------------

st.title("📩 Email Preflight Checker")
st.caption("Checks SPF, DKIM, DMARC and FCrDNS for outbound sending IPs")

col1, col2 = st.columns(2)

with col1:
    domain = st.text_input("Main Domain", "loanpathwaynow.com")
    selector = st.text_input("DKIM Selector", "pat084")
    from_email = st.text_input("From Email", "insights@loanpathwaynow.com")

with col2:
    return_path = st.text_input("Return-Path", "insights@loanpathwaynow.com")
    ips_raw = st.text_area(
        "Outbound IPs (comma or line separated)",
        "194.34.237.62\n194.34.237.63"
    )

run = st.button("Run Preflight Check", use_container_width=True)

# -------------------------
# Run
# -------------------------

if run:

    ip_list = re.split(r"[,\n]+", ips_raw)
    ip_list = [x.strip() for x in ip_list if x.strip()]

    results = []

    # SPF
    spf = get_spf_record(domain)

    # DKIM
    dkim_ok = check_dkim_selector(selector, domain)

    # DMARC
    dmarc = get_dmarc_record(domain)

    from_domain = parse_domain(from_email)
    rp_domain = parse_domain(return_path)

    dmarc_alignment = (
        get_base_domain(from_domain) == get_base_domain(domain)
        or get_base_domain(rp_domain) == get_base_domain(domain)
    )

    # Per IP checks
    for ip in ip_list:

        row = {"IP": ip}

        # SPF
        if spf and ip_authorized_in_spf(ip, spf):
            row["SPF"] = f"PASS with IP {ip}"
        else:
            row["SPF"] = "FAIL"

        # DKIM
        row["DKIM"] = f"PASS with domain {domain}" if dkim_ok else "FAIL"

        # DMARC
        row["DMARC"] = "PASS" if dmarc and dmarc_alignment else "FAIL"

        # FCrDNS
        ok, host = forward_confirm(ip)
        row["FCrDNS"] = "PASS" if ok else "FAIL"
        row["PTR Hostname"] = host if host else "No PTR"

        results.append(row)

    df = pd.DataFrame(results)

    # -------------------------
    # Dashboard Cards
    # -------------------------

    st.subheader("Summary")

    c1, c2, c3, c4 = st.columns(4)

    all_spf = all("PASS" in x for x in df["SPF"])
    all_dkim = all("PASS" in x for x in df["DKIM"])
    all_dmarc = all("PASS" in x for x in df["DMARC"])
    all_rdns = all("PASS" in x for x in df["FCrDNS"])

    c1.metric("SPF", "PASS" if all_spf else "FAIL")
    c2.metric("DKIM", "PASS" if all_dkim else "FAIL")
    c3.metric("DMARC", "PASS" if all_dmarc else "FAIL")
    c4.metric("FCrDNS", "PASS" if all_rdns else "FAIL")

    # -------------------------
    # Gmail Style Output
    # -------------------------

    st.subheader("Gmail Show Original Preview")

    first = df.iloc[0]

    st.code(first["SPF"])
    st.code(first["DKIM"])
    st.code("DMARC: " + first["DMARC"])

    # -------------------------
    # Table
    # -------------------------

    st.subheader("Detailed Results")
    st.dataframe(df, use_container_width=True)

    # -------------------------
    # Final Verdict
    # -------------------------

    st.subheader("Launch Readiness")

    if all_spf and all_dkim and all_dmarc and all_rdns:
        st.success("✅ READY FOR FIRST HIT")
    else:
        st.error("❌ NOT READY FOR FIRST HIT")
