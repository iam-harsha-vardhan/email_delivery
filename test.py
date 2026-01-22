import streamlit as st
import pandas as pd
from io import StringIO

st.set_page_config(page_title="Daily ORS Comparison", layout="wide")

st.title("📊 Today vs Yesterday ORS Report")

# ---------------- TIME DROPDOWN ----------------
time_slot = st.selectbox(
    "Select Report Time",
    [
        "4:30 PM", "5:30 PM", "6:30 PM",
        "7:30 PM", "8:30 PM", "9:30 PM", "10:30 PM"
    ],
    index=4
)

st.caption(f"📌 Selected Time: {time_slot}")

# ---------------- INPUT BOXES ----------------
col1, col2 = st.columns(2)

with col1:
    st.subheader("📥 Today Report (Paste from Excel)")
    today_text = st.text_area(
        "Paste TODAY data here",
        height=300,
        placeholder="Paste Excel data including headers"
    )

with col2:
    st.subheader("📥 Yesterday Report (Paste from Excel)")
    yesterday_text = st.text_area(
        "Paste YESTERDAY data here",
        height=300,
        placeholder="Paste Excel data including headers"
    )

# ---------------- PROCESS ----------------
if st.button("🚀 Generate Comparison"):

    try:
        today_df = pd.read_csv(StringIO(today_text), sep="\t")
        yesterday_df = pd.read_csv(StringIO(yesterday_text), sep="\t")

        # Clean totals row if present
        today_df = today_df[~today_df["Usergroup"].str.contains("Totals", na=False)]
        yesterday_df = yesterday_df[~yesterday_df["Usergroup"].str.contains("Totals", na=False)]

        # Sort inside inputs (for cross-verification)
        today_df = today_df.sort_values("Usergroup")
        yesterday_df = yesterday_df.sort_values("Usergroup")

        # Rename columns for clarity
        today_df = today_df.rename(columns={
            "Sent": "Sent_Today",
            "Delivered": "Delivered_Today",
            "Genuine Unique Opens": "Opens_Today",
            "Genuine Open Rate": "OR_Today",
            "Unique Unsubs": "Unsubs_Today",
            "Unsub Rate": "UnsubRate_Today"
        })

        yesterday_df = yesterday_df.rename(columns={
            "Sent": "Sent_Yesterday",
            "Delivered": "Delivered_Yesterday",
            "Genuine Unique Opens": "Opens_Yesterday",
            "Genuine Open Rate": "OR_Yesterday",
            "Unique Unsubs": "Unsubs_Yesterday",
            "Unsub Rate": "UnsubRate_Yesterday"
        })

        # Merge
        final_df = pd.merge(
            today_df,
            yesterday_df,
            on="Usergroup",
            how="outer"
        ).fillna(0)

        # Delta columns
        final_df["OR_Delta"] = final_df["OR_Today"] - final_df["OR_Yesterday"]
        final_df["Unsub_Delta"] = final_df["UnsubRate_Today"] - final_df["UnsubRate_Yesterday"]
        final_df["Opens_Delta"] = final_df["Opens_Today"] - final_df["Opens_Yesterday"]

        # Sort final output
        final_df = final_df.sort_values("Usergroup")

        # ---------------- DISPLAY ----------------
        st.subheader("📊 Combined Report")
        st.dataframe(final_df, use_container_width=True)

        # ---------------- TOTALS ----------------
        st.subheader("📌 Totals")
        totals = final_df.select_dtypes(include="number").sum().to_frame("Total")
        st.dataframe(totals)

        # ---------------- DOWNLOAD ----------------
        excel_buffer = StringIO()
        final_df.to_csv(excel_buffer, index=False)

        st.download_button(
            label="⬇ Download Combined Report (CSV)",
            data=excel_buffer.getvalue(),
            file_name=f"ORS_Comparison_{time_slot.replace(':','')}.csv",
            mime="text/csv"
        )

    except Exception as e:
        st.error(f"⚠ Error processing data: {e}")
