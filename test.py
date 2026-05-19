# ============================================
# app.py
# Hourly Deliverability Comparison Dashboard
# Streamlit Single File App
# ============================================

import streamlit as st
import pandas as pd
import os
import json
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px

# ============================================
# PAGE CONFIG
# ============================================

st.set_page_config(
    page_title="Deliverability Dashboard",
    layout="wide",
    page_icon="📊"
)

# ============================================
# CUSTOM CSS
# ============================================

st.markdown("""
<style>

.main {
    background-color: #0e1117;
}

.block-container {
    padding-top: 1rem;
}

.metric-card {
    background: linear-gradient(135deg,#111827,#1f2937);
    border-radius: 18px;
    padding: 18px;
    border: 1px solid #374151;
    box-shadow: 0px 0px 12px rgba(0,0,0,0.4);
}

.metric-title {
    color: #9CA3AF;
    font-size: 14px;
}

.metric-value {
    color: white;
    font-size: 34px;
    font-weight: bold;
}

.section-title {
    color: white;
    font-size: 26px;
    font-weight: bold;
    margin-top: 20px;
}

.compare-card {
    background-color: #111827;
    border-radius: 14px;
    padding: 16px;
    margin-bottom: 12px;
    border: 1px solid #2d3748;
}

.bar-container {
    width: 100%;
    height: 34px;
    display: flex;
    border-radius: 10px;
    overflow: hidden;
    margin-top: 10px;
    margin-bottom: 8px;
}

.green-bar {
    height: 100%;
    background: linear-gradient(90deg,#16a34a,#22c55e);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-weight: bold;
    font-size: 14px;
}

.red-bar {
    height: 100%;
    background: linear-gradient(90deg,#dc2626,#ef4444);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-weight: bold;
    font-size: 14px;
}

.small-text {
    color: #9CA3AF;
    font-size: 13px;
}

</style>
""", unsafe_allow_html=True)

# ============================================
# DATA STORAGE
# ============================================

DATA_FOLDER = "stored_reports"

if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER)

# ============================================
# HEADER
# ============================================

st.markdown("""
<div class='section-title'>
🚀 Deliverability Intelligence Dashboard
</div>
""", unsafe_allow_html=True)

# ============================================
# SIDEBAR
# ============================================

st.sidebar.header("📂 Upload Hourly Report")

selected_date = st.sidebar.date_input(
    "Select Report Date",
    datetime.now()
)

hour_options = [
    "4:30 PM",
    "5:30 PM",
    "6:30 PM",
    "7:30 PM",
    "8:30 PM",
    "9:30 PM",
    "10:30 PM"
]

selected_hour = st.sidebar.selectbox(
    "Select Hour",
    hour_options
)

uploaded_file = st.sidebar.file_uploader(
    "Upload CSV or Excel",
    type=["csv", "xlsx"]
)

# ============================================
# SAVE REPORT
# ============================================

def save_uploaded_report(df, report_date, report_hour):

    date_str = report_date.strftime("%Y-%m-%d")

    filename = f"{date_str}_{report_hour.replace(':','-').replace(' ','_')}.csv"

    path = os.path.join(DATA_FOLDER, filename)

    df.to_csv(path, index=False)

# ============================================
# LOAD REPORT
# ============================================

def load_report(report_date, report_hour):

    date_str = report_date.strftime("%Y-%m-%d")

    filename = f"{date_str}_{report_hour.replace(':','-').replace(' ','_')}.csv"

    path = os.path.join(DATA_FOLDER, filename)

    if os.path.exists(path):
        return pd.read_csv(path)

    return None

# ============================================
# AUTO DELETE OLD FILES (30 DAYS)
# ============================================

def cleanup_old_reports():

    now = datetime.now()

    for file in os.listdir(DATA_FOLDER):

        path = os.path.join(DATA_FOLDER, file)

        created_time = datetime.fromtimestamp(os.path.getctime(path))

        if now - created_time > timedelta(days=30):
            os.remove(path)

cleanup_old_reports()

# ============================================
# LOAD FILE
# ============================================

if uploaded_file:

    if uploaded_file.name.endswith(".csv"):
        current_df = pd.read_csv(uploaded_file)
    else:
        current_df = pd.read_excel(uploaded_file)

    save_uploaded_report(
        current_df,
        selected_date,
        selected_hour
    )

    st.sidebar.success("Report Saved Successfully")

else:

    current_df = load_report(
        selected_date,
        selected_hour
    )

# ============================================
# YESTERDAY DATA
# ============================================

yesterday_date = selected_date - timedelta(days=1)

yesterday_df = load_report(
    yesterday_date,
    selected_hour
)

# ============================================
# VALIDATION
# ============================================

if current_df is None:

    st.warning("Upload current report")

    st.stop()

if yesterday_df is None:

    st.warning("Yesterday report not available")

# ============================================
# COLUMN STANDARDIZATION
# ============================================

rename_map = {
    "Genuine Unique Opens": "GUO",
    "Genuine Open Rate": "GOR",
    "Unique Unsubs": "Unsubs"
}

current_df.rename(columns=rename_map, inplace=True)

if yesterday_df is not None:
    yesterday_df.rename(columns=rename_map, inplace=True)

# ============================================
# KPI TOTALS
# ============================================

def get_total(df, column):

    if column not in df.columns:
        return 0

    return round(df[column].sum(), 2)

today_sent = get_total(current_df, "Sent")
today_delivered = get_total(current_df, "Delivered")
today_guo = get_total(current_df, "GUO")
today_gor = round(current_df["GOR"].mean(), 2)
today_unsubs = get_total(current_df, "Unsubs")
today_unsub_rate = round(current_df["Unsub Rate"].mean(), 2)

if yesterday_df is not None:

    y_sent = get_total(yesterday_df, "Sent")
    y_delivered = get_total(yesterday_df, "Delivered")
    y_guo = get_total(yesterday_df, "GUO")
    y_gor = round(yesterday_df["GOR"].mean(), 2)
    y_unsubs = get_total(yesterday_df, "Unsubs")
    y_unsub_rate = round(yesterday_df["Unsub Rate"].mean(), 2)

else:

    y_sent = y_delivered = y_guo = y_gor = y_unsubs = y_unsub_rate = 0

# ============================================
# KPI CARDS
# ============================================

st.markdown("---")

col1, col2, col3 = st.columns(3)

with col1:

    st.markdown(f"""
    <div class='metric-card'>
        <div class='metric-title'>📨 Sent</div>
        <div class='metric-value'>{today_sent:,}</div>
    </div>
    """, unsafe_allow_html=True)

with col2:

    st.markdown(f"""
    <div class='metric-card'>
        <div class='metric-title'>👀 GUO</div>
        <div class='metric-value'>{today_guo:,}</div>
    </div>
    """, unsafe_allow_html=True)

with col3:

    st.markdown(f"""
    <div class='metric-card'>
        <div class='metric-title'>📈 GOR</div>
        <div class='metric-value'>{today_gor}%</div>
    </div>
    """, unsafe_allow_html=True)

# ============================================
# DOMINANCE BAR
# ============================================

def comparison_bar(today, yesterday, reverse=False):

    if today == 0 and yesterday == 0:
        return ""

    maximum = max(today, yesterday)

    today_width = int((today / maximum) * 100)
    yesterday_width = int((yesterday / maximum) * 100)

    if reverse:

        today_good = today < yesterday

    else:

        today_good = today > yesterday

    if today_good:

        today_class = "green-bar"
        yesterday_class = "red-bar"

    else:

        today_class = "red-bar"
        yesterday_class = "green-bar"

    html = f"""
    <div class='bar-container'>

        <div class='{today_class}'
            style='width:{today_width}%'>
            {today}
        </div>

        <div class='{yesterday_class}'
            style='width:{yesterday_width}%'>
            {yesterday}
        </div>

    </div>
    """

    return html

# ============================================
# USERGROUP COMPARISON
# ============================================

st.markdown("---")

st.markdown("""
<div class='section-title'>
📊 Usergroup Comparison
</div>
""", unsafe_allow_html=True)

if yesterday_df is not None:

    groups = current_df["Usergroup"].unique()

    for group in groups:

        today_row = current_df[
            current_df["Usergroup"] == group
        ]

        y_row = yesterday_df[
            yesterday_df["Usergroup"] == group
        ]

        if len(today_row) == 0 or len(y_row) == 0:
            continue

        today_row = today_row.iloc[0]
        y_row = y_row.iloc[0]

        st.markdown(f"""
        <div class='compare-card'>

        <h4 style='color:white'>
        {group}
        </h4>

        <div class='small-text'>
        GOR Comparison
        </div>

        {comparison_bar(
            round(today_row['GOR'],2),
            round(y_row['GOR'],2)
        )}

        <div class='small-text'>
        GUO Comparison
        </div>

        {comparison_bar(
            int(today_row['GUO']),
            int(y_row['GUO'])
        )}

        <div class='small-text'>
        Unsub Comparison
        </div>

        {comparison_bar(
            int(today_row['Unsubs']),
            int(y_row['Unsubs']),
            reverse=True
        )}

        </div>
        """, unsafe_allow_html=True)

# ============================================
# TREND GRAPH
# ============================================

st.markdown("---")

st.markdown("""
<div class='section-title'>
📈 Overall Trend
</div>
""", unsafe_allow_html=True)

metrics = pd.DataFrame({
    "Metric": ["Sent","Delivered","GUO","GOR","Unsubs"],
    "Today": [
        today_sent,
        today_delivered,
        today_guo,
        today_gor,
        today_unsubs
    ],
    "Yesterday": [
        y_sent,
        y_delivered,
        y_guo,
        y_gor,
        y_unsubs
    ]
})

fig = go.Figure()

fig.add_trace(go.Bar(
    x=metrics["Metric"],
    y=metrics["Today"],
    name="Today"
))

fig.add_trace(go.Bar(
    x=metrics["Metric"],
    y=metrics["Yesterday"],
    name="Yesterday"
))

fig.update_layout(
    template="plotly_dark",
    barmode="group",
    height=500
)

st.plotly_chart(fig, use_container_width=True)

# ============================================
# STORED REPORTS
# ============================================

st.markdown("---")

st.markdown("""
<div class='section-title'>
🗂 Stored Reports
</div>
""", unsafe_allow_html=True)

files = sorted(os.listdir(DATA_FOLDER), reverse=True)

report_df = pd.DataFrame({
    "Stored Files": files
})

st.dataframe(
    report_df,
    use_container_width=True,
    height=250
)

# ============================================
# FOOTER
# ============================================

st.markdown("---")

st.caption(
    "⚡ Streamlit Deliverability Intelligence Dashboard"
)
