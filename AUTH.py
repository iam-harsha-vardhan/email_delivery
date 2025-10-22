def parse_email_message(msg):
    """Extracts all relevant details from an email message object."""
    data = {
        "Subject": decode_mime_words(msg.get("Subject", "No Subject")),
        "Date": msg.get("Date", "No Date"),
        "SPF": "-", "DKIM": "-", "DMARC": "-", "Domain": "-",
        "Type": "-", "Sub ID": "-", 
        "Message-ID": msg.get("Message-ID", "") # <-- CHANGE: Get raw Message-ID here
    }

    headers = ''.join(f"{header}: {value}\n" for header, value in msg.items())
    match_auth = re.search(r'Authentication-Results:.*?smtp.mailfrom=([\w\.-]+)', headers, re.I)
    if match_auth:
        data["Domain"] = match_auth.group(1).lower()
    else:
        from_header = decode_mime_words(msg.get('From', ''))
        match = re.search(r'@([\w\.-]+)', from_header)
        if match:
            data["Domain"] = match.group(1).lower()

    spf_match = re.search(r'spf=(\w+)', headers, re.I)
    dkim_match = re.search(r'dkim=(\w+)', headers, re.I)
    dmarc_match = re.search(r'dmarc=(\w+)', headers, re.I)
    if spf_match: data["SPF"] = spf_match.group(1).lower()
    if dkim_match: data["DKIM"] = dkim_match.group(1).lower()
    if dmarc_match: data["DMARC"] = dmarc_match.group(1).lower()

    # --- START OF CHANGES ---

    # 1. Decode the Message-ID in case it's MIME encoded
    raw_message_id = data["Message-ID"] # Get the raw ID we stored earlier
    decoded_message_id = decode_mime_words(raw_message_id)
    data["Message-ID"] = decoded_message_id # Overwrite with the decoded version

    # 2. Use the DECODED message_id for all checks
    if decoded_message_id:
        # Original Sub ID logic (now uses decoded string)
        sub_id_match = re.search(r'(GTC-[^@_]+|GMFP-[^@_]+)', decoded_message_id, re.I)
        if sub_id_match:
            data["Sub ID"] = sub_id_match.group(1)
        
        # Convert decoded ID to lower for new type checks
        msg_id_lower = decoded_message_id.lower() 

        # 3. Add new Type logic
        if 'gtc' in msg_id_lower:
            data["Type"] = 'FPTC'
        elif 'gmfp' in msg_id_lower:
            data["Type"] = 'FP'
        elif 'grm' in msg_id_lower:  # <-- NEW
            data["Type"] = 'FPR'
        elif 'ajtc' in msg_id_lower: # <-- NEW
            data["Type"] = 'AJTC'
        elif 'agm' in msg_id_lower:  # <-- NEW
            data["Type"] = 'AJ ' # With the space, as you requested
            
    # --- END OF CHANGES ---
            
    return data
