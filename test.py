# ---------- Build presence keys and asset map (shared data structures) ----------
all_keys = set()
email_presence_map = {}  # { email_address: set(message_keys) }
new_email_keys = set()
valid_emails = [r["Email"] for i, r in st.session_state.creds_df.iterrows() if r["Email"] in st.session_state.mailbox_data]

# Asset map for Sub-ID consensus logic
asset_map = {}  # {(domain, from, subject): {"accounts": set(), "subids": set(), "subid_accounts": set(), "rows": []}}

for email_addr in valid_emails:
    df_acc = st.session_state.mailbox_data[email_addr]["df"]
    keys = set()
    for _, row in df_acc.iterrows():
        # presence key (unchanged)
        msg_key = (row["Domain"], row["Subject"], row["From"], row["SPF"], row["DKIM"], row["DMARC"], row.get("Sub ID", "-"))
        keys.add(msg_key)
        if row.get("is_new", False):
            new_email_keys.add(msg_key)
        # build asset_map
        asset_key = (row.get("Domain", "-"), row.get("From", "-"), row.get("Subject", "-"))
        asset = asset_map.setdefault(asset_key, {"accounts": set(), "subids": set(), "subid_accounts": set(), "rows": []})
        asset["accounts"].add(email_addr)
        sid = row.get("Sub ID", "-")
        if sid and sid != "-":
            asset["subids"].add(sid)
            asset["subid_accounts"].add(email_addr)
        # record whether this specific row was new (for later highlighting)
        asset["rows"].append({
            "account": email_addr,
            "UID": row.get("UID"),
            "Message-ID": row.get("Message-ID"),
            "Sub ID": sid or "-",
            "Type": row.get("Type", "-"),
            "SPF": row.get("SPF"),
            "DKIM": row.get("DKIM"),
            "DMARC": row.get("DMARC"),
            "is_new": bool(row.get("is_new", False))
        })

    email_presence_map[email_addr] = keys
    all_keys.update(keys)

# ---------- TOP: Sub-ID Consensus (full width) ----------
st.subheader(f"🔎 Sub-ID Consensus (≥ {required_accounts_count} accounts)")

subid_rows = []
for (domain, from_val, subject), info in asset_map.items():
    present_count = len(info["accounts"])
    subid_accounts_count = len(info["subid_accounts"])
    # Strict requirement: both presence and subid must reach the threshold
    if present_count >= required_accounts_count and subid_accounts_count >= required_accounts_count:
        subid_list = sorted(list(info["subids"]))
        accounts_list = sorted(list(info["accounts"]))
        # Determine is_new for this asset (if any underlying row is_new)
        asset_is_new = any(r.get("is_new", False) for r in info["rows"])
        row = {
            "Domain": domain,
            "From": from_val,
            "Subject": subject,
            "Present In (Count)": present_count,
            "Sub-ID Accounts (Count)": subid_accounts_count,
            "Accounts": ", ".join([a.split('@')[0] for a in accounts_list]),
            "Sub IDs (all)": ", ".join(subid_list) if subid_list else "-",
            "is_new": asset_is_new
        }
        # Per-account tick columns for quick glance
        for email_addr in valid_emails:
            header = email_addr.split('@')[0]
            row[header] = "✅" if email_addr in info["accounts"] else "❌"
        subid_rows.append(row)

if subid_rows:
    subid_df = pd.DataFrame(subid_rows)
    subid_df = subid_df.sort_values(by=["Sub-ID Accounts (Count)", "Present In (Count)", "Domain"], ascending=[False, False, True], ignore_index=True)
    # Apply the same green highlight rule to this table using the is_new flag we added
    st.dataframe(subid_df.style.apply(highlight_new_rows, axis=1), use_container_width=True)
else:
    st.info(f"No assets found that contain Sub-IDs in at least {required_accounts_count} accounts and are present in ≥ {required_accounts_count} accounts.")

st.markdown("---")

# ---------- MIDDLE: Email Presence Table (centered) ----------
# Build rows exactly as before (unchanged keys/logic)
rows = []
if all_keys:
    sorted_keys = sorted(list(all_keys), key=lambda k: (k not in new_email_keys, k[0], k[1]))
    for (domain, subject, from_val, spf, dkim, dmarc, subid) in sorted_keys:
        row_data = {
            "Domain": domain, "From": from_val, "Subject": subject,
            "Sub ID": subid,
            "Auth": "Pass" if all(res == 'pass' for res in [spf, dkim, dmarc]) else "Fail",
            "is_new": (domain, subject, from_val, spf, dkim, dmarc, subid) in new_email_keys
        }
        for email_addr in valid_emails:
            is_present = (domain, subject, from_val, spf, dkim, dmarc, subid) in email_presence_map[email_addr]
            col_header = email_addr.split('@')[0]
            row_data[col_header] = "✅" if is_present else "❌"
        rows.append(row_data)

    # Put the presence table in the middle column for visual centering
    left_col, mid_col, right_col = st.columns([1, 8, 1])
    with mid_col:
        st.subheader("📋 Email Presence Table (Newest on Top)")
        presence_df = pd.DataFrame(rows)
        # Keep exact previous behavior but apply green highlight to new rows
        st.dataframe(presence_df.style.apply(highlight_new_rows, axis=1), hide_index=True, column_config={"is_new": None}, use_container_width=True)
else:
    st.info("No emails found in the active accounts.")

st.markdown("---")
