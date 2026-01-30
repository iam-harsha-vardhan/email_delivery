import streamlit as st
import pandas as pd
import requests
import time
from urllib.parse import urlparse
import io

# --- Page Configuration ---
st.set_page_config(
    page_title="Redirect Validator Tool",
    page_icon="🔄",
    layout="wide"
)

# --- CSS for Styling ---
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        font-weight: 700;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #64748B;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
    }
    .success-box {
        padding: 1rem;
        background-color: #D1FAE5;
        border-left: 5px solid #10B981;
        color: #065F46;
        margin-bottom: 1rem;
    }
    .error-box {
        padding: 1rem;
        background-color: #FEE2E2;
        border-left: 5px solid #EF4444;
        color: #991B1B;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# --- Helper Functions ---

def normalize_url(url):
    """Ensures URL has a schema."""
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def check_redirect(source_url, expected_target):
    """
    Checks the redirect chain of a URL.
    Returns dictionary with status details.
    """
    source_url = normalize_url(source_url)
    expected_target = normalize_url(expected_target)
    
    result = {
        "Source URL": source_url,
        "Expected Target": expected_target,
        "Actual Target": "N/A",
        "Status Code": "N/A",
        "Match Status": "Error",
        "Notes": ""
    }

    try:
        # Perform the request
        # We define a custom User-Agent to avoid being blocked by some firewalls
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        
        response = requests.get(source_url, headers=headers, allow_redirects=True, timeout=10)
        
        result["Actual Target"] = response.url
        result["Status Code"] = response.status_code
        
        # Logic to check if match
        # We normalize both to ignore trailing slashes or www variations if needed
        clean_actual = response.url.rstrip('/')
        clean_expected = expected_target.rstrip('/')
        
        if clean_expected in clean_actual:
            result["Match Status"] = "✅ MATCH"
            result["Notes"] = "Redirected successfully."
        elif response.status_code >= 400:
             result["Match Status"] = "❌ BROKEN"
             result["Notes"] = f"Client/Server Error: {response.status_code}"
        else:
            result["Match Status"] = "⚠️ MISMATCH"
            result["Notes"] = "Redirected to unexpected URL."
            
    except requests.exceptions.Timeout:
        result["Match Status"] = "⏱️ TIMEOUT"
        result["Notes"] = "Server took too long to respond."
    except requests.exceptions.ConnectionError:
        result["Match Status"] = "🚫 CONNECTION ERROR"
        result["Notes"] = "DNS failure or refused connection."
    except Exception as e:
        result["Match Status"] = "❗ ERROR"
        result["Notes"] = str(e)
        
    return result

def generate_sample_file():
    """Generates a sample Excel file in memory."""
    # Sheet 1: Feeds and their Targets
    df_feeds = pd.DataFrame({
        'Feed Name': ['TechNews', 'FashionDaily', 'CryptoWatch'],
        'Target Website': ['https://technews.example.com', 'https://fashion.example.com', 'https://crypto.example.com']
    })
    
    # Sheet 2: Domains belonging to feeds
    df_domains = pd.DataFrame({
        'Feed Name': ['TechNews', 'TechNews', 'FashionDaily', 'CryptoWatch'],
        'Source Domain': ['old-tech-blog.com', 'tech-updates.net', 'my-fashion-vlog.org', 'coin-tracker.io']
    })
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_feeds.to_excel(writer, sheet_name='Target_Rules', index=False)
        df_domains.to_excel(writer, sheet_name='Source_Domains', index=False)
    
    return output.getvalue()

# --- Main App Interface ---

st.markdown('<div class="main-header">Redirect Validator Tool 🔄</div>', unsafe_allow_html=True)
st.markdown("""
This tool checks if your old domains are correctly redirecting to their intended target websites.
Upload an Excel file with two sheets:
1. **Target_Rules**: Maps `Feed Name` to `Target Website`
2. **Source_Domains**: Maps `Source Domain` to `Feed Name`
""")

# --- Sidebar: Template Download ---
with st.sidebar:
    st.header("1. Get Template")
    st.write("Don't have the file format?")
    sample_data = generate_sample_file()
    st.download_button(
        label="📥 Download Sample Excel",
        data=sample_data,
        file_name="redirect_validator_template.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        help="Click to download a sample file structure."
    )
    st.info("Use this file as a starting point. Do not rename the columns.")

# --- Main Section: Upload and Process ---
st.header("2. Upload & Validate")
uploaded_file = st.file_uploader("Upload your Excel file", type=['xlsx', 'xls'])

if uploaded_file:
    try:
        # Load sheets
        xls = pd.ExcelFile(uploaded_file)
        
        # Allow user to select sheets if names differ, but default to first and second
        sheet_names = xls.sheet_names
        
        col1, col2 = st.columns(2)
        with col1:
            rules_sheet = st.selectbox("Select 'Target Rules' Sheet", sheet_names, index=0)
        with col2:
            domains_sheet = st.selectbox("Select 'Source Domains' Sheet", sheet_names, index=1 if len(sheet_names) > 1 else 0)
            
        if st.button("🚀 Start Validation", type="primary"):
            
            # Data Loading
            df_rules = pd.read_excel(uploaded_file, sheet_name=rules_sheet)
            df_domains = pd.read_excel(uploaded_file, sheet_name=domains_sheet)
            
            # Simple Column Cleanup (remove spaces)
            df_rules.columns = df_rules.columns.str.strip()
            df_domains.columns = df_domains.columns.str.strip()
            
            # Find common column for Feed Name
            # We assume column 0 is the key if names don't match exactly, or look for specific names
            # For robustness, let's normalize headers
            
            # Attempt to merge
            # Finding the link column (Feed Name)
            common_cols = list(set(df_rules.columns) & set(df_domains.columns))
            
            if not common_cols:
                st.error("Could not find a common column (like 'Feed Name') between the two sheets to link them.")
                st.stop()
                
            link_col = common_cols[0] # Take the first common column
            
            st.write(f"Linking sheets on column: **{link_col}**")
            
            # Merge to get expected target for each source
            merged_df = pd.merge(df_domains, df_rules, on=link_col, how='left')
            
            # Identify specific columns for URLS
            # We look for columns containing 'url', 'website', 'domain', 'link'
            def find_url_col(df):
                for col in df.columns:
                    if any(x in col.lower() for x in ['target', 'dest', 'website']):
                        return col
                return None
            
            def find_source_col(df):
                for col in df.columns:
                    if any(x in col.lower() for x in ['source', 'domain', 'origin']):
                        return col
                return None

            target_col = find_url_col(df_rules)
            source_col = find_source_col(df_domains)
            
            if not target_col or not source_col:
                st.warning("Could not auto-detect URL columns. Please rename columns in Excel to include 'Source' and 'Target' or 'Website'.")
                st.stop()
                
            # Prepare for processing
            results = []
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            total_rows = len(merged_df)
            
            # --- Processing Loop ---
            for index, row in merged_df.iterrows():
                # Update progress
                progress = (index + 1) / total_rows
                progress_bar.progress(progress)
                
                source = row[source_col]
                target = row[target_col]
                
                status_text.text(f"Checking {index + 1}/{total_rows}: {source}...")
                
                if pd.isna(target):
                    res = {
                        "Source URL": source,
                        "Expected Target": "MISSING IN RULES",
                        "Actual Target": "-",
                        "Status Code": "-",
                        "Match Status": "⚠️ CONFIG ERROR",
                        "Notes": f"No target found for feed '{row[link_col]}'"
                    }
                else:
                    res = check_redirect(source, target)
                
                results.append(res)
            
            progress_bar.empty()
            status_text.empty()
            
            # Create Results DataFrame
            results_df = pd.DataFrame(results)
            
            # --- Display Stats ---
            st.divider()
            st.header("3. Validation Report")
            
            stat_col1, stat_col2, stat_col3 = st.columns(3)
            with stat_col1:
                match_count = len(results_df[results_df['Match Status'].str.contains("MATCH")])
                st.metric("Successful Redirects", match_count)
            with stat_col2:
                mismatch_count = len(results_df[results_df['Match Status'].str.contains("MISMATCH")])
                st.metric("Mismatched Targets", mismatch_count)
            with stat_col3:
                error_count = len(results_df) - match_count - mismatch_count
                st.metric("Errors/Broken", error_count)
            
            # Visual Feedback
            if mismatch_count == 0 and error_count == 0:
                st.markdown('<div class="success-box">✅ All checks passed! Every domain redirects to the correct intented website.</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="error-box">⚠️ Issues detected. Please download the report to fix unmatched domains.</div>', unsafe_allow_html=True)

            # Display Data
            st.subheader("Detailed Results")
            
            # Color code the dataframe for display
            def highlight_status(val):
                color = 'red' if 'MISMATCH' in val or 'ERROR' in val or 'BROKEN' in val else 'green'
                return f'color: {color}; font-weight: bold'

            st.dataframe(
                results_df.style.map(highlight_status, subset=['Match Status']),
                use_container_width=True
            )
            
            # --- Download Logic ---
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                results_df.to_excel(writer, index=False, sheet_name="Validation_Report")
            
            st.download_button(
                label="📥 Download Full Report (Excel)",
                data=buffer.getvalue(),
                file_name=f"redirect_report_{time.strftime('%Y%m%d')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                type="primary"
            )

    except Exception as e:
        st.error(f"An error occurred while processing the file: {e}")
