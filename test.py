import streamlit as st
        ]

    # ==========================================
    # METRICS
    # ==========================================

    total = len(df)

    passed = len(df[df["Auth Result"] == "PASS"])

    failed = len(df[df["Auth Result"] == "FAIL"])

    spam = len(df[df["Mailbox"] == "Spam"])

    inbox = len(df[df["Mailbox"] == "Inbox"])

    m1, m2, m3, m4, m5 = st.columns(5)

    m1.metric("Total", total)
    m2.metric("Passed", passed)
    m3.metric("Failed", failed)
    m4.metric("Inbox", inbox)
    m5.metric("Spam", spam)

    # ==========================================
    # FAILED EMAILS
    # ==========================================

    failed_df = df[df["Auth Result"] == "FAIL"]

    if not failed_df.empty:
        st.subheader("❌ Failed Emails")
        st.dataframe(failed_df, use_container_width=True)

    # ==========================================
    # MAIN TABLE
    # ==========================================

    st.subheader("📬 Email Intelligence Table")

    st.dataframe(df, use_container_width=True)

    # ==========================================
    # EXPORTS
    # ==========================================

    csv = df.to_csv(index=False).encode('utf-8')

    st.download_button(
        "⬇ Download CSV",
        csv,
        file_name="enterprise_email_monitor.csv",
        mime="text/csv"
    )
