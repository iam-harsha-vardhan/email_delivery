# Gmail Show Original Simulator


import streamlit as st
import dns.resolver
import socket
import ipaddress
import pandas as pd
from typing import List

st.set_page_config(page_title='Gmail Show Original Simulator', layout='wide')

# ---------- Helpers ----------
def get_txt(domain):
    try:
        return [b''.join(r.strings).decode() for r in dns.resolver.resolve(domain, 'TXT')]
    except Exception:
        return []


def get_a_records(domain):
    try:
        return [r.to_text() for r in dns.resolver.resolve(domain, 'A')]
    except Exception:
        return []


def spf_record(domain):
    for t in get_txt(domain):
        if t.lower().startswith('v=spf1'):
            return t
    return None


def ip_in_spf(ip, spf):
    if not spf:
        return False
    parts = spf.split()
    for p in parts:
        if p.startswith('ip4:'):
            net = p.replace('ip4:', '')
            try:
                if '/' in net:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False):
                        return True
                elif ip == net:
                    return True
            except Exception:
                pass
    return False


def dmarc_record(domain):
    vals = get_txt(f'_dmarc.{domain}')
    for v in vals:
        if v.lower().startswith('v=dmarc1'):
            return v
    return None


def dkim_exists(selector, domain):
    vals = get_txt(f'{selector}._domainkey.{domain}')
    return any('p=' in v for v in vals)


def rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def fcrdns(ip):
    host = rdns(ip)
    if not host:
        return False, None
    try:
        ips = socket.gethostbyname_ex(host)[2]
        return ip in ips, host
    except Exception:
        return False, host


def base_domain(v):
    parts = v.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return v

# ---------- UI ----------
st.title('📩 Gmail Show Original Simulator')

with st.sidebar:
    st.header('Checks')
    do_spf = st.checkbox('SPF', True)
    do_dkim = st.checkbox('DKIM', True)
    do_dmarc = st.checkbox('DMARC', True)
    do_fcrdns = st.checkbox('FCrDNS / rDNS', False)

main_domain = st.text_input('Main Domain', 'demo.com')
aliases = st.text_area('Alias / Subdomains (one per line)', 'updates.demo.com\nmail.demo.com')
ips_text = st.text_area('Existing IPs (optional, one per line)', '')
selectors = st.text_input('DKIM Selectors (comma separated)', 'pmta')
from_email = st.text_input('From Email', 'news@demo.com')
return_path = st.text_input('Return-Path Domain', 'bounce.demo.com')
dkim_d = st.text_input('DKIM d= Domain', 'demo.com')

if st.button('Run Simulation'):
    rows = []
    assets = [main_domain] + [x.strip() for x in aliases.splitlines() if x.strip()]
    manual_ips = [x.strip() for x in ips_text.splitlines() if x.strip()]
    selectors_list = [x.strip() for x in selectors.split(',') if x.strip()]

    for asset in assets:
        ips = manual_ips if manual_ips else get_a_records(asset)
        if not ips:
            ips = ['No A record']
        for ip in ips:
            row = {'Asset': asset, 'IP': ip}
            if do_spf:
                spf = spf_record(base_domain(return_path)) or spf_record(asset) or spf_record(main_domain)
                if ip != 'No A record' and ip_in_spf(ip, spf):
                    row['SPF'] = f'PASS with IP {ip}'
                else:
                    row['SPF'] = 'FAIL'
            if do_dkim:
                passed = any(dkim_exists(s, dkim_d) for s in selectors_list)
                row['DKIM'] = f"PASS with domain {dkim_d}" if passed else 'FAIL'
            if do_dmarc:
                frm = from_email.split('@')[-1]
                aligned = base_domain(frm) == base_domain(dkim_d) or base_domain(frm) == base_domain(return_path)
                row['DMARC'] = 'PASS' if dmarc_record(base_domain(frm)) and aligned else 'FAIL'
            if do_fcrdns and ip != 'No A record':
                ok, host = fcrdns(ip)
                row['FCrDNS'] = 'PASS' if ok else 'FAIL'
                row['PTR'] = host or 'No PTR'
            rows.append(row)

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)

    st.subheader('Gmail Show Original Preview')
    if not df.empty:
        sample = df.iloc[0].to_dict()
        if do_spf: st.code(sample.get('SPF',''))
        if do_dkim: st.code(sample.get('DKIM',''))
        if do_dmarc: st.code('DMARC: ' + sample.get('DMARC',''))

