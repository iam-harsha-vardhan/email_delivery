# =========================
# 🔬 DEEP TRACKING MODULE
# =========================

import urllib.parse

# Session flag to toggle deep section
if "show_tracking_section" not in st.session_state:
    st.session_state.show_tracking_section = False

st.markdown("---")

if st.button("🔗 Extract Tracking Links"):
    st.session_state.show_tracking_section = not st.session_state.show_tracking_section

# Only show section when toggled
if st.session_state.show_tracking_section:

    st.subheader("🔬 Deep Tracking Extraction")

    domain_input = st.text_area(
        "Paste tracking domains (one per line)",
        height=150,
        help="Only these domains will be scanned for tracking links."
    )

    if st.button("🚀 Run Link Extraction"):

        if not domain_input.strip():
            st.warning("Please paste at least one domain.")
        elif st.session_state.df.empty:
            st.warning("No emails loaded.")
        else:

            selected_domains = [
                d.strip().lower()
                for d in domain_input.splitlines()
                if d.strip()
            ]

            tracking_results = []

            try:
                imap = imaplib.IMAP4_SSL("imap.gmail.com")
                imap.login(st.session_state.email_input, st.session_state.password_input)
                imap.select("inbox")

                for _, row in st.session_state.df.iterrows():

                    if row["Domain"] not in selected_domains:
                        continue

                    msg_id = row["Message-ID"]
                    if not msg_id:
                        continue

                    status, data = imap.search(None, f'(HEADER Message-ID "{msg_id}")')
                    ids = data[0].split()
                    if not ids:
                        continue

                    status, msg_data = imap.fetch(ids[0], '(BODY.PEEK[])')

                    for part in msg_data:
                        if not isinstance(part, tuple):
                            continue

                        msg = email.message_from_bytes(part[1])

                        headers_str = ''.join(f"{h}: {v}\n" for h, v in msg.items())

                        tracking_domain = ""
                        list_unsub = "-"
                        unsub_link = "-"
                        open_pixel = "-"
                        logo = "-"

                        # ---- Extract List-Unsubscribe ----
                        lu_match = re.search(r'List-Unsubscribe:.*', headers_str, re.I)
                        if lu_match:
                            urls = re.findall(r'<([^>]+)>', lu_match.group(0))
                            for u in urls:
                                if u.startswith("http"):
                                    list_unsub = u
                                    tracking_domain = urllib.parse.urlparse(u).netloc.lower()
                                    break

                        # ---- Extract HTML ----
                        body_html = ""
                        if msg.is_multipart():
                            for p in msg.walk():
                                if p.get_content_type() == "text/html":
                                    body_html = p.get_payload(decode=True).decode(errors="ignore")
                                    break
                        else:
                            if msg.get_content_type() == "text/html":
                                body_html = msg.get_payload(decode=True).decode(errors="ignore")

                        # ---- Find tracking links ----
                        if tracking_domain and body_html:
                            links = re.findall(r'https?://[^\s"\'<>]+', body_html)
                            tracking_links = [l for l in links if tracking_domain in l]

                            for link in tracking_links:
                                l = link.lower()

                                if "unsub" in l:
                                    unsub_link = link
                                elif re.search(r'pixel|open|track|view', l):
                                    open_pixel = link
                                elif re.search(r'\.(png|jpg|jpeg|gif|svg)$', l):
                                    logo = link

                        tracking_results.append({
                            "Subject": row["Subject"],
                            "Date": row["Date"],
                            "Domain": row["Domain"],
                            "Tracking Domain": tracking_domain if tracking_domain else "-",
                            "List-Unsubscribe": list_unsub,
                            "Unsubscribe Link": unsub_link,
                            "Open Pixel": open_pixel,
                            "Logo": logo
                        })

                imap.logout()

                if tracking_results:
                    tracking_df = pd.DataFrame(tracking_results)
                    tracking_df.index = tracking_df.index + 1

                    st.subheader("📊 Tracking Link Results")
                    st.dataframe(tracking_df, use_container_width=True)
                else:
                    st.info("No matching tracking links found for selected domains.")

            except Exception as e:
                st.error(f"Error during tracking extraction: {str(e)}")
