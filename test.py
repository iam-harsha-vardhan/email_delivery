# ---------- MIDDLE: Email Presence Table (centered) with qualifying Sub-IDs as last column ----------
# Build a quick mapping of asset_key -> qualifying subids (those that passed the top/main rules)
# asset_map is already built above and required_accounts_count is set.
qualifying_subids = {}  # {(domain, from, subject): [subid1, subid2, ...]}
for (domain, from_val, subject), info in asset_map.items():
    # asset must be present in >= N accounts
    if len(info["accounts"]) < required_accounts_count:
        continue
    # For each subid, check it is present in >= N accounts (same rule used for the top table)
    for subid in info["subids"]:
        # find accounts that have this subid for this asset
        subid_accounts = {r["account"] for r in info["rows"] if (r.get("Sub ID") or "-") == subid}
        if len(subid_accounts) >= required_accounts_count:
            qualifying_subids.setdefault((domain, from_val, subject), []).append(subid)

# Now build the presence table rows (same keys as before) but include qualifying subids as last column
rows = []
if all_keys:
    # sort keys roughly as before (new first then by domain/subject)
    sorted_keys = sorted(list(all_keys), key=lambda k: (k not in new_email_keys, k[0], k[1]))
    for (domain, subject, from_val, spf, dkim, dmarc, subid) in sorted_keys:
        # Determine latest time across accounts for this presence key (if available)
        latest_dt = None
        latest_str = "-"
        for email_addr in valid_emails:
            df_acc = st.session_state.mailbox_data[email_addr]["df"]
            matches = df_acc[
                (df_acc["Domain"] == domain) &
                (df_acc["Subject"] == subject) &
                (df_acc["From"] == from_val) &
                (df_acc.get("Sub ID", "-") == subid)
            ]
            for _, mrow in matches.iterrows():
                dt = mrow.get("Date_dt")
                if dt is not None:
                    if latest_dt is None or dt > latest_dt:
                        latest_dt = dt
                        latest_str = mrow.get("Date") or latest_str

        # Find qualifying subids for this asset (domain, from, subject)
        qual_key = (domain, from_val, subject)
        qual_list = qualifying_subids.get(qual_key, [])
        # We include only those qualifying subids — if none, the cell will be "-"
        # NOTE: the presence row still exists even if the asset had no qualifying subids (subid cell will be "-")
        subids_cell = ", ".join(qual_list) if qual_list else "-"

        row_data = {
            "Domain": domain,
            "From": from_val,
            "Subject": subject,
            "Sub ID (raw)": subid,                # original per-row Sub-ID (keeps backward compatibility)
            "Time (IST)": latest_str,
            "Auth": "Pass" if all(res == 'pass' for res in [spf, dkim, dmarc]) else "Fail",
            "is_new": (domain, subject, from_val, spf, dkim, dmarc, subid) in new_email_keys,
            "Sub IDs (qualifying)": subids_cell   # <- this will be placed as the last visible column
        }

        for email_addr in valid_emails:
            is_present = (domain, subject, from_val, spf, dkim, dmarc, subid) in email_presence_map[email_addr]
            col_header = email_addr.split('@')[0]
            row_data[col_header] = "✅" if is_present else "❌"
        # helper key for sorting presence by time
        row_data["Date_dt_sort"] = latest_dt
        rows.append(row_data)

    # Convert to DataFrame and sort by Date_dt_sort desc (newest first)
    presence_df = pd.DataFrame(rows)
    if "Date_dt_sort" in presence_df.columns:
        presence_df = presence_df.sort_values(by=["Date_dt_sort"], ascending=[False], na_position='last', ignore_index=True)

    # Center the table visually and set column order similar to Sub-ID table
    left_col, mid_col, right_col = st.columns([1, 8, 1])
    with mid_col:
        st.subheader("📋 Email Presence Table (Newest on Top)")
        if not presence_df.empty:
            per_account_cols = [e.split('@')[0] for e in valid_emails]
            # Choose display ordering:
            # Domain, From, Subject, Sub ID (raw) (kept), Time (IST), per-account ticks..., Sub IDs (qualifying) (last), is_new (hidden)
            display_cols = ["Domain", "From", "Subject", "Sub ID (raw)", "Time (IST)"] + per_account_cols + ["Sub IDs (qualifying)", "is_new"]
            # Reindex to ensure consistent column set and order
            presence_df = presence_df.reindex(columns=display_cols, fill_value="-")
            st.dataframe(presence_df.style.apply(highlight_new_rows, axis=1), hide_index=True, column_config={"is_new": None}, use_container_width=True)
        else:
            st.info("No presence rows to show.")
else:
    st.info("No emails found in the active accounts.")
