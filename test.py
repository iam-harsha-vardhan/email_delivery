import streamlit as st
import pandas as pd
import requests
import io
import time
import urllib3
import concurrent.futures
from urllib.parse import urlparse

# 1. Hide "Insecure Request" warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Page Config ---
st.set_page_config(page_title="Redirect Validator", page_icon="✅", layout="wide")

# --- CSS Styling ---
st.markdown("""
<style>
    .stButton>button { width: 100%; height: 3em; border-radius: 8px; font-weight: bold; }
    div[data-testid="column"] { text-align: center; }
</style>
""", unsafe_allow_html=True)

# --- Helper Functions ---

def clean_url_logic(url):
    """Strips protocol and www for comparison."""
    if not url: return ""
    u = str(url).strip().lower()
    if u.startswith("https://"): u = u[8:]
    if u.startswith("http://"): u = u[7:]
    if u.startswith("www."): u = u[4:]
    return u.rstrip('/')

def make_request(url):
    """Tries to connect with REAL BROWSER HEADERS."""
    target_url = url.strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url 

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    try:
        # Try 1: As provided
        response = requests.get(target_url, headers=headers, allow_redirects=True, timeout=10, verify=False)
        return response
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout, requests.exceptions.SSLError):
        # Try 2: Swap protocol
        try:
            if target_url.startswith("http://"):
                retry_url = target_url.replace("http://", "https://", 1)
            else:
                retry_url = target_url.replace("https://", "http://", 1)
            
            response = requests.get(retry_url, headers=headers, allow_redirects=True, timeout=10, verify=False)
            return response
        except Exception as e:
            raise e

def check_redirect(source, expected_target):
    # Typo Check
    if expected_target and "httpts" in str(expected_target):
        return {
            "Source Domain": source, "Expected Target": expected_target,
            "Actual Final URL": "-", "Status": "❗ TYPO", "Details": "Fix 'httpts' in Excel"
        }

    core_expected = clean_url_logic(expected_target)
    
    result = {
        "Source Domain": source,
        "Expected Target": expected_target,
        "Actual Final URL": "-",
        "Status": "Checking...",
        "Details": ""
    }
    
    try:
        response = make_request(source)
        
        final_url = response.url
        result["Actual Final URL"] = final_url
        core_actual = clean_url_logic(final_url)
        
        # --- COMPARISON LOGIC ---
        if core_expected == core_actual:
            result["Status"] = "✅ MATCH"
            result["Details"] = "OK"
        elif core_expected in core_actual:
            result["Status"] = "✅ MATCH"
            result["Details"] = "OK (Sub-page)"
        else:
            if response.status_code == 403:
                if core_expected in core_actual:
                    result["Status"] = "✅ MATCH"
                    result["Details"] = "OK (Ignore 403)"
                else:
                    result["Status"] = "❌ BROKEN"
                    result["Details"] = "Access Denied (403)"
            elif response.status_code >= 400:
                result["Status"] = "❌ BROKEN"
                result["Details"] = f"Page Error: {response.status_code}"
            else:
                result["Status"] = "❌ MISMATCH"
                result["Details"] = "Redirected to wrong site"

    except requests.exceptions.SSLError:
        result["Status"] = "🔒 SSL ISSUE"
        result["Details"] = "Enable SSL on Source Domain"
    except requests.exceptions.ConnectionError:
        result["Status"] = "🚫 DOWN"
        result["Details"] = "Connection Refused (DNS/Server)"
    except requests.exceptions.Timeout:
        result["Status"] = "⏱️ TIMEOUT"
        result["Details"] = "Server too slow (>10s)"
    except Exception as e:
        result["Status"] = "❗ ERROR"
        result["Details"] = str(e)
        
    return result

# Wrapper for Threading
def process_single_row(row_data):
    src = row_data['src']
    tgt = row_data['tgt']
    
    if pd.isna(tgt) or str(tgt).strip() == "":
        return {
            "Source Domain": src, "Status": "⚠️ NO TARGET", 
            "Actual Final URL": "-", "Details": "No target in rules sheet"
        }
    else:
        return check_redirect(src, tgt)

def convert_df_to_excel(df):
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    return buffer.getvalue()

def generate_sample_file():
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        pd.DataFrame({'Feed Name': ['ExampleFeed'], 'Target Website': ['arise-cash.com']}).to_excel(writer, sheet_name='Target_Rules', index=False)
        pd.DataFrame({'Feed Name': ['ExampleFeed'], 'Source Domain': ['arisefinancepro.com']}).to_excel(writer, sheet_name='Source_Domains', index=False)
    return output.getvalue()

# --- Main App ---

st.title("Redirect Validator 🚀")

with st.sidebar:
    st.header("Actions")
    st.download_button("📥 Download Template", generate_sample_file(), "redirect_template.xlsx")

uploaded_file = st.file_uploader("Upload Excel File", type=['xlsx', 'xls'])

if uploaded_file:
    if st.button("🚀 Start Validation", type="primary"):
        
        # UI Elements
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            # 1. Read Data
            xls = pd.ExcelFile(uploaded_file)
            all_sheets = xls.sheet_names
            sheet_rules = next((s for s in all_sheets if 'target' in s.lower() or 'rule' in s.lower()), all_sheets[0])
            sheet_domains = next((s for s in all_sheets if 'source' in s.lower() or 'domain' in s.lower()), all_sheets[1] if len(all_sheets)>1 else all_sheets[0])
            
            df_rules = pd.read_excel(uploaded_file, sheet_name=sheet_rules)
            df_domains = pd.read_excel(uploaded_file, sheet_name=sheet_domains)
            
            df_rules.columns = df_rules.columns.str.strip()
            df_domains.columns = df_domains.columns.str.strip()
            
            common_col = list(set(df_rules.columns) & set(df_domains.columns))[0]
            
            # --- Remove Duplicates in Rules ---
            rules_before = len(df_rules)
            df_rules = df_rules.drop_duplicates(subset=[common_col])
            
            # Merge
            merged = pd.merge(df_domains, df_rules, on=common_col, how='left')
            
            target_col = next(c for c in df_rules.columns if 'target' in c.lower() or 'web' in c.lower())
            source_col = next(c for c in df_domains.columns if 'source' in c.lower() or 'domain' in c.lower())
            
            # 2. Prepare Data for Threads (STRICT FILTERING)
            tasks = []
            for index, row in merged.iterrows():
                src = row[source_col]
                
                # --- FILTER LOGIC: Skip empty or 'nan' rows ---
                if pd.isna(src) or str(src).strip() == "" or str(src).lower() == "nan":
                    continue
                
                tasks.append({'src': src, 'tgt': row[target_col]})
            
            total_tasks = len(tasks)
            results = []
            completed_count = 0
            
            if total_tasks == 0:
                st.warning("No valid domains found to check.")
            else:
                # 3. FAST Multi-threaded Processing (50 workers)
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    futures = [executor.submit(process_single_row, task) for task in tasks]
                    
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        results.append(result)
                        completed_count += 1
                        
                        # Update progress UI
                        progress_bar.progress(completed_count / total_tasks)
                        status_text.markdown(f"**⚡ Speed Mode:** Checking **{completed_count}/{total_tasks}**")

                # 4. Clean up UI
                progress_bar.empty()
                status_text.success(f"✅ Finished checking {total_tasks} valid domains!")
                
                # 5. Process Results
                df_res = pd.DataFrame(results)
                
                # Filter Failed
                df_failed = df_res[~df_res['Status'].str.contains("MATCH")]

                # START INDEX AT 1
                df_res.index = df_res.index + 1
                
                def color_status(val):
                    if 'MATCH' in str(val): return 'background-color: #d1fae5; color: #065f46; font-weight: bold'
                    if 'SSL' in str(val): return 'background-color: #ffedd5; color: #c2410c; font-weight: bold'
                    return 'background-color: #fee2e2; color: #991b1b; font-weight: bold'

                st.subheader("Results Table")
                # HEIGHT=600 makes it scrollable vertically
                st.dataframe(df_res.style.map(color_status, subset=['Status']), use_container_width=True, height=600)
                
                st.divider()
                st.subheader("Download Reports")
                
                btn_col1, btn_col2 = st.columns(2)
                timestamp = time.strftime('%Y%m%d_%H%M')
                
                with btn_col1:
                    st.download_button(
                        label="Download Whole Report",
                        data=convert_df_to_excel(df_res),
                        file_name=f"Full_Report_{timestamp}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        type="secondary",
                        use_container_width=True
                    )
                    
                with btn_col2:
                    st.download_button(
                        label="Download Failed Only",
                        data=convert_df_to_excel(df_failed),
                        file_name=f"Failed_Report_{timestamp}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        type="primary",
                        use_container_width=True
                    )

        except Exception as e:
            st.error(f"An error occurred: {e}")
