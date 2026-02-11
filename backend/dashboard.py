import streamlit as st
import requests
import pandas as pd
from datetime import datetime

API = "http://127.0.0.1:8000"

st.set_page_config(page_title="LogSight Dashboard", layout="wide")
st.markdown("<h1 style='text-align:left'>      LogSight</h1>", unsafe_allow_html=True)

left, right = st.columns([2,1])

with left:
    st.subheader("Controls")
    if st.button("Refresh Summary"):
        pass

    search_term = st.text_input("Search logs (regex)", value="", placeholder="e.g. error|denied|timeout")
    submitted = st.button("Search")

    quick = st.columns(4)
    if quick[0].button("Errors"):
        search_term = "error"
        submitted = True
    if quick[1].button("Denied"):
        search_term = "denied|sandbox"
        submitted = True
    if quick[2].button("Failed Auth"):
        search_term = "failed password|authentication failure|invalid user"
        submitted = True
    if quick[3].button("Network"):
        search_term = "timeout|connection|UDP|HTTP load failed"
        submitted = True

    st.write("---")
    st.subheader("Brute-force & Alerts")
    bf_col1, bf_col2 = st.columns(2)
    if bf_col1.button("Detect Brute-force (>=20)"):
        try:
            r = requests.get(f"{API}/detect_bruteforce?min_attempts=20", timeout=30).json()
            st.success("Brute-force scan complete")
            st.json(r)
        except Exception as e:
            st.error("Failed to contact API: " + str(e))
    if bf_col2.button("Check Alerts"):
        try:
            r = requests.get(f"{API}/alerts", timeout=20).json()
            st.json(r)
        except Exception as e:
            st.error("Failed to contact API: " + str(e))

with right:
    st.subheader("Summary")
    try:
        r = requests.get(f"{API}/summary", timeout=60).json()
        total = r.get("total_lines", 0)
        top5 = r.get("top5", [])
        st.metric("Total log lines", f"{total:,}")
        if top5:
            df = pd.DataFrame(top5, columns=["message","count"])
            df["count"] = df["count"].astype(int)
            st.table(df.head(5))
    except Exception as e:
        st.error("Cannot fetch summary: " + str(e))

st.write("---")
st.subheader("Search Results")
if submitted and search_term.strip():
    with st.spinner("Searching logs..."):
        try:
            r = requests.post(f"{API}/search_fast", json={"pattern": search_term}, timeout=120).json()
            st.write(f"Matches: {r.get('matches',0)}")
            lines = r.get("lines", [])[:200]
            if lines:
                # show first 20, collapsible show more
                for ln in lines[:20]:
                    st.code(ln)
                if len(lines) > 20:
                    with st.expander(f"Show remaining {len(lines)-20} results"):
                        for ln in lines[20:]:
                            st.code(ln)
            else:
                st.info("No matches found.")
        except Exception as e:
            st.error("Search failed: " + str(e))
else:
    st.info("Enter a regex and press Search or use Quick buttons.")

st.write("---")
st.subheader("Top IPs (recent)")
try:
    r = requests.get(f"{API}/top_ips?limit=10", timeout=30).json()
    top_ips = r.get("top_ips", [])
    if top_ips:
        df_ips = pd.DataFrame(top_ips, columns=["ip","count"])
        st.table(df_ips)
        st.bar_chart(df_ips.set_index("ip"))
    else:
        st.info("No IP addresses found in logs.")
except Exception as e:
    st.error("Failed to fetch top IPs: " + str(e))

st.write("---")
st.subheader("Quick Diagnostics")
diag = st.button("Run quick diagnostics")
if diag:
    try:
        r1 = requests.get(f"{API}/top_ips?limit=10", timeout=20).json()
        r2 = requests.get(f"{API}/detect_bruteforce?min_attempts=10", timeout=20).json()
        st.write("Top IPs:")
        st.json(r1)
        st.write("Brute-force suspects (>=10):")
        st.json(r2)
    except Exception as e:
        st.error("Diagnostics failed: " + str(e))

st.write("---")
st.caption("LogSight — local log analyzer. Backend: http://127.0.0.1:8000")



