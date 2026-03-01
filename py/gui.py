#!/usr/bin/env python3
"""
gui.py - FR-8: Streamlit GUI for the Network Traffic Analyzer.
Usage: streamlit run py/gui.py

Calls ./app subcommands via subprocess and displays results in-browser.
"""

import streamlit as st
import subprocess
import os
import sys

# Absolute path to the ./app binary (relative to this script's parent dir)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_BIN  = os.path.join(BASE_DIR, 'app')
DEF_CSV  = os.path.join(BASE_DIR, 'data', 'network_data.csv')
OUT_DIR  = os.path.join(BASE_DIR, 'out')

def run_cmd(args: list[str], csv_path: str) -> str:
    """Run ./app with given args and return stdout+stderr as string."""
    cmd = [APP_BIN, '--input', csv_path] + args
    st.code(' '.join(cmd), language='bash')
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout + (('\n[STDERR]\n' + result.stderr) if result.stderr else '')
    except FileNotFoundError:
        return f"[ERROR] Binary not found: {APP_BIN}\nPlease run `make` first."
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out (>30s)"

# ─── Page config ────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Network Traffic Analyzer",
    page_icon="🌐",
    layout="wide",
)

st.title("🌐 Network Traffic Analyzer")
st.caption("Network Traffic Analyzer & Anomaly Detector — C++ CLI + Python GUI")

# ─── Sidebar: file selector ──────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")
    csv_path = st.text_input("CSV Data File", value=DEF_CSV)
    st.markdown("---")
    st.markdown("**Quick actions:**")
    if st.button("📊 Graph Stats"):
        st.session_state['result'] = run_cmd(['stats'], csv_path)
        st.session_state['cmd'] = 'stats'

# ─── Tabs ───────────────────────────────────────────────────────────────────
tabs = st.tabs(["📈 Sort Traffic", "🔐 HTTPS", "↗️ One-way",
                "🗺️ Path Find", "⭐ Star Topology", "🚨 Security Rule",
                "📤 Export Subgraph"])

# Tab 0: Sort by total traffic
with tabs[0]:
    st.subheader("FR-3.1 Sort All Nodes by Total Traffic")
    top_k = st.number_input("Top K", min_value=1, max_value=500, value=20, key='sort_k')
    if st.button("🔍 Run Sort", key='btn_sort'):
        out = run_cmd(['sort', '--top', str(top_k)], csv_path)
        st.text(out)

# Tab 1: HTTPS
with tabs[1]:
    st.subheader("FR-3.2 Sort Nodes by HTTPS Traffic (TCP+Port 443)")
    top_k2 = st.number_input("Top K", min_value=1, max_value=500, value=20, key='https_k')
    if st.button("🔒 Run HTTPS Sort", key='btn_https'):
        out = run_cmd(['sort-https', '--top', str(top_k2)], csv_path)
        st.text(out)

# Tab 2: One-way
with tabs[2]:
    st.subheader("FR-3.3 Nodes with Outbound Ratio > Threshold")
    col1, col2 = st.columns(2)
    threshold = col1.number_input("Threshold", min_value=0.0, max_value=1.0, value=0.8, step=0.05)
    top_k3 = col2.number_input("Top K", min_value=1, max_value=500, value=50, key='ow_k')
    if st.button("↗️ Run One-way", key='btn_ow'):
        out = run_cmd(['sort-oneway', '--threshold', str(threshold), '--top', str(top_k3)], csv_path)
        st.text(out)

# Tab 3: Path finding
with tabs[3]:
    st.subheader("FR-4 Path Finding: BFS (min hops) + Dijkstra (min congestion)")
    col1, col2 = st.columns(2)
    src_ip = col1.text_input("Source IP", value="115.156.142.194")
    dst_ip = col2.text_input("Destination IP", value="18.182.32.116")
    metric = st.radio("Metric", ["hop", "congestion", "both"], horizontal=True)
    if st.button("🗺️ Find Path", key='btn_path'):
        out = run_cmd(['path', '--src', src_ip, '--dst', dst_ip, '--metric', metric], csv_path)
        st.text(out)

# Tab 4: Star topology
with tabs[4]:
    st.subheader("FR-5 Star Topology Detection")
    min_leaves = st.number_input("Min Leaves", min_value=1, max_value=500, value=20)
    if st.button("⭐ Detect Stars", key='btn_stars'):
        out = run_cmd(['stars', '--min-leaves', str(min_leaves)], csv_path)
        st.text(out)

# Tab 5: Security rule
with tabs[5]:
    st.subheader("FR-6 IP Range Security Rule")
    col1, col2, col3 = st.columns(3)
    ip1   = col1.text_input("Controlled IP (ip1)", value="115.156.142.194")
    ip_lo = col2.text_input("Range Low",  value="18.182.32.100")
    ip_hi = col3.text_input("Range High", value="18.182.32.200")
    mode  = st.radio("Mode", ["deny", "allow"], horizontal=True)
    if st.button("🚨 Apply Rule", key='btn_rule'):
        out = run_cmd(['rule', 'iprange', '--mode', mode,
                       '--ip1', ip1, '--low', ip_lo, '--high', ip_hi], csv_path)
        st.text(out)

# Tab 6: Export subgraph
with tabs[6]:
    st.subheader("FR-9 Export Connected Subgraph")
    exp_ip   = st.text_input("IP Address", value="115.156.142.194")
    out_csv  = os.path.join(OUT_DIR, 'subgraph_edges.csv')
    out_html = os.path.join(OUT_DIR, 'subgraph.html')
    if st.button("📤 Export Subgraph", key='btn_exp'):
        out = run_cmd(['export-subgraph', '--ip', exp_ip, '--out', out_csv], csv_path)
        st.text(out)

    if st.button("🎨 Visualize (requires networkx + pyvis)", key='btn_vis'):
        vis_script = os.path.join(BASE_DIR, 'py', 'visualize_subgraph.py')
        # Derive node file matching C++ logic (basename_nodes.csv)
        node_csv = out_csv.replace(".csv", "_nodes.csv")
        
        result = subprocess.run([sys.executable, vis_script,
                                 '--edges', out_csv, 
                                 '--nodes', node_csv, 
                                 '--out', out_html],
                                capture_output=True, text=True)
        if result.returncode != 0:
            st.error(f"Visualization failed:\n{result.stderr}")
        else:
            st.text(result.stdout)
            if os.path.exists(out_html):
                st.success(f"Enhanced 'Bloom' Visualization ready!")
                with open(out_html, 'r') as f:
                    html_content = f.read()
                st.components.v1.html(html_content, height=800, scrolling=True)

# ─── Sidebar stats result ────────────────────────────────────────────────────
if 'result' in st.session_state:
    with st.sidebar:
        st.markdown("---")
        st.subheader("Stats Result")
        st.text(st.session_state['result'])
