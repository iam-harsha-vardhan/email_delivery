def fetch_last_n_for_account_fast(email_addr, password, domain_substring, max_messages=DEFAULT_MAX_MESSAGES, uid_scan_limit=UID_SCAN_LIMIT):
    """
    Faster fetch: perform UID SEARCH on server (FROM) to get matching UIDs, then fetch only the newest max_messages bodies.
    Returns list of rows: {Account, UID, Subject, Display, HTML, Date}
    """
    rows = []
    try:
        imap = imaplib.IMAP4_SSL('imap.gmail.com')
        imap.login(email_addr.strip(), password.strip())
        imap.select('inbox')

        # Server-side search: prefer FROM "domain" if provided
        if domain_substring:
            try:
                status, data = imap.uid('search', None, 'FROM', f'"{domain_substring}"')
            except Exception:
                status, data = imap.uid('search', None, f'FROM "{domain_substring}"')
        else:
            status, data = imap.uid('search', None, 'ALL')

        if status != 'OK' or not data or not data[0]:
            imap.logout()
            return rows

        matched_uids = data[0].split()
        if not matched_uids:
            imap.logout()
            return rows

        # limit candidate UIDs for safety, and pick newest max_messages
        candidate_uids = matched_uids[-uid_scan_limit:] if len(matched_uids) > uid_scan_limit else matched_uids
        selected_uids = candidate_uids[-int(max_messages):] if len(candidate_uids) > int(max_messages) else candidate_uids

        # fetch full bodies in batches (faster than per-UID)
        batch_size = 100
        for i in range(0, len(selected_uids), batch_size):
            chunk = selected_uids[i:i+batch_size]
            uid_seq = b','.join(chunk)
            try:
                res, md = imap.uid('fetch', uid_seq, '(BODY.PEEK[])')
            except Exception:
                # fallback to per-UID fetch if batch fails
                for u in chunk:
                    try:
                        u_str = u.decode()
                        r2, md2 = imap.uid('fetch', u_str, '(BODY.PEEK[])')
                        if r2 != 'OK' or not md2:
                            continue
                        raw_msg_bytes = None
                        for p in md2:
                            if isinstance(p, tuple) and p[1]:
                                raw_msg_bytes = p[1]
                                break
                        if not raw_msg_bytes:
                            continue
                        msg = email.message_from_bytes(raw_msg_bytes)
                        subject, display, html_creative = extract_subject_display_html_from_msg(msg)
                        raw_date = msg.get('Date','')
                        try:
                            formatted_date = parsedate_to_datetime(raw_date).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%d-%b-%Y %I:%M %p')
                        except Exception:
                            formatted_date = raw_date
                        rows.append({'Account': email_addr, 'UID': u_str, 'Subject': subject, 'Display': display, 'HTML': html_creative, 'Date': formatted_date})
                    except Exception:
                        continue
                continue

            # iterate returned tuples and extract messages
            for part in md:
                if not isinstance(part, tuple):
                    continue
                raw_msg_bytes = part[1]
                if not raw_msg_bytes:
                    continue
                try:
                    msg = email.message_from_bytes(raw_msg_bytes)
                except Exception:
                    continue
                # try to get UID from meta if available
                uid_found = None
                try:
                    meta = part[0].decode('utf-8', errors='ignore')
                    m = re.search(r'UID\s+(\d+)', meta)
                    if m:
                        uid_found = m.group(1)
                except Exception:
                    uid_found = None
                uid_val = uid_found if uid_found else (chunk[0].decode() if chunk else '')
                subject, display, html_creative = extract_subject_display_html_from_msg(msg)
                raw_date = msg.get('Date','')
                try:
                    formatted_date = parsedate_to_datetime(raw_date).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%d-%b-%Y %I:%M %p')
                except Exception:
                    formatted_date = raw_date
                rows.append({'Account': email_addr, 'UID': uid_val, 'Subject': subject, 'Display': display, 'HTML': html_creative, 'Date': formatted_date})

        imap.logout()
    except imaplib.IMAP4.error as e:
        st.error(f'IMAP error for {email_addr}: {e}')
        return rows
    except Exception as e:
        st.error(f'Error fetching {email_addr}: {e}')
        return rows

    return rows
