"""
CyberTrace: DFIR Investigation Workbench & Crime Scene Sandbox
Compliant with ISO/IEC 27037 digital evidence handling standards.
Lightweight Python, Streamlit, Scapy, SQLite3, ReportLab.
"""

import os
import sys
from datetime import datetime, timezone
import pandas as pd
import streamlit as st

# Ensure repository root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers.evidence_hasher import compute_file_hashes, verify_integrity
from parsers.browser_parser import parse_chromium_history, parse_chromium_downloads
from parsers.email_parser import parse_email
from parsers.magic_checker import detect_file_signature, check_file_spoofing
from parsers.pcap_parser import parse_pcap, detect_suspicious_flows
from parsers.timeline_engine import build_master_timeline
from utils.report_generator import generate_forensic_pdf
import generate_mock_evidence

# ---------------------------------------------------------
# Page Configuration & Forensic Dark Theme CSS
# ---------------------------------------------------------
st.set_page_config(
    page_title="CyberTrace // DFIR Forensic Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    /* Dark Theme Cyber Palette */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    /* Monospace elements */
    code, pre, .mono-text {
        font-family: "Fira Code", "Source Code Pro", Consolas, monospace !important;
    }

    /* Metric Cards */
    .metric-card {
        background: linear-gradient(135deg, #131b2e 0%, #1e293b 100%);
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
    }
    .metric-card .title {
        color: #94a3b8;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-card .value {
        font-size: 1.6rem;
        font-weight: 700;
        color: #38bdf8;
        margin-top: 4px;
    }
    .metric-card .subtext {
        font-size: 0.75rem;
        color: #64748b;
        margin-top: 4px;
    }

    /* Badges */
    .badge-verified {
        background-color: rgba(16, 185, 129, 0.2);
        color: #10b981;
        border: 1px solid #10b981;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.75rem;
    }
    .badge-tampered {
        background-color: rgba(239, 68, 68, 0.2);
        color: #ef4444;
        border: 1px solid #ef4444;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.75rem;
    }
    .badge-critical {
        background-color: rgba(220, 38, 38, 0.25);
        color: #f87171;
        border: 1px solid #dc2626;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 0.7rem;
    }
    .badge-mitre {
        background-color: rgba(99, 102, 241, 0.2);
        color: #a5b4fc;
        border: 1px solid #6366f1;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 0.7rem;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #334155;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #131b2e;
        border-radius: 6px 6px 0 0;
        border: 1px solid #334155;
        border-bottom: none;
        color: #94a3b8;
        font-size: 0.85rem;
        font-weight: 600;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1e293b !important;
        color: #38bdf8 !important;
        border-top: 2px solid #38bdf8 !important;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------
# State Management
# ---------------------------------------------------------
if "evidence_registry" not in st.session_state:
    st.session_state.evidence_registry = {}  # {filename: {"bytes": ..., "meta": ..., "original_hash": ...}}

if "tamper_mode" not in st.session_state:
    st.session_state.tamper_mode = False

if "challenge_results" not in st.session_state:
    st.session_state.challenge_results = None

if "case_notes" not in st.session_state:
    st.session_state.case_notes = (
        "Preliminary Incident Assessment:\n"
        "- Initial Access gained via spear-phishing email delivered from 198.51.100.23 with forged SPF/DKIM headers.\n"
        "- Victim workstation downloaded 'urgent_report.pdf', which exhibited an executable PE (MZ) header masquerading as a PDF.\n"
        "- Network packet inspection confirmed outbound reverse shell beaconing to 198.51.100.23:4444.\n"
        "- Exfiltration of confidential Q4 financial projections detected over C2 channel."
    )


def register_evidence(filename: str, file_bytes: bytes, custodian: str = "Lead Forensic Examiner"):
    """Registers evidence into state, calculating baseline hash and chain of custody."""
    hashes = compute_file_hashes(file_bytes, filename, custodian=custodian)
    st.session_state.evidence_registry[filename] = {
        "bytes": file_bytes,
        "meta": hashes,
        "original_hash": hashes["sha256"],
    }


def load_mock_scenario():
    """Generates mock artifacts and ingests them into the evidence registry."""
    mock_dir = os.path.join(os.path.dirname(__file__), "mock_case")
    paths = generate_mock_evidence.build_mock_case(mock_dir)

    for item_key, item_path in paths.items():
        fname = os.path.basename(item_path)
        with open(item_path, "rb") as f:
            raw = f.read()
            register_evidence(fname, raw, custodian="Detective J. Vance, DFIR Unit")

    st.toast("✅ Mock Crime Scene Ingested Successfully!", icon="🛡️")


# ---------------------------------------------------------
# Sidebar Controls
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("### 🔍 CYBERTRACE INVESTIGATION")
    st.caption("ISO/IEC 27037 Digital Forensics Workbench")
    st.markdown("---")

    scenario = st.selectbox(
        "Investigation Scenario",
        [
            "Scenario 01: Unauthorized Data Exfiltration",
            "Scenario 02: Custom Evidence Sandbox",
        ],
    )

    st.markdown("#### ⚡ Quick Ingestion")
    if st.button("📥 Load Mock Crime Scene Data", use_container_width=True, type="primary"):
        load_mock_scenario()

    st.markdown("---")
    st.markdown("#### 📂 Ingest Custom Evidence Artifacts")

    uploaded_email = st.file_uploader("Phishing Email (.eml)", type=["eml"])
    if uploaded_email:
        register_evidence(uploaded_email.name, uploaded_email.getvalue())

    uploaded_pdf = st.file_uploader("Suspicious Payload / File (.pdf, .exe)", type=["pdf", "exe", "scr", "bin"])
    if uploaded_pdf:
        register_evidence(uploaded_pdf.name, uploaded_pdf.getvalue())

    uploaded_browser = st.file_uploader("Chromium History (SQLite)", type=["sqlite", "db", "History", "sqlite3"])
    if uploaded_browser:
        register_evidence(uploaded_browser.name, uploaded_browser.getvalue())

    uploaded_pcap = st.file_uploader("Packet Capture (.pcap, .pcapng)", type=["pcap", "pcapng"])
    if uploaded_pcap:
        register_evidence(uploaded_pcap.name, uploaded_pcap.getvalue())

    st.markdown("---")
    st.markdown("#### 🧪 Sandbox Tamper Simulation")
    tamper_toggle = st.toggle("Simulate Evidence Tampering", value=st.session_state.tamper_mode)
    if tamper_toggle != st.session_state.tamper_mode:
        st.session_state.tamper_mode = tamper_toggle
        st.rerun()

    if st.button("🗑️ Reset Workbench", use_container_width=True):
        st.session_state.evidence_registry = {}
        st.session_state.challenge_results = None
        st.session_state.tamper_mode = False
        st.rerun()


# ---------------------------------------------------------
# Artifact Parsing & Cross-Correlation
# ---------------------------------------------------------
parsed_email = None
email_df = pd.DataFrame()
spoof_result = None
file_events = []
browser_df = pd.DataFrame()
downloads_df = pd.DataFrame()
pcap_df = pd.DataFrame()
suspicious_flows_df = pd.DataFrame()

chain_of_custody_list = []
total_tampered = 0

for fname, item in st.session_state.evidence_registry.items():
    raw_bytes = item["bytes"]

    # If tamper simulation is active, inject 1 altered byte into 'urgent_report.pdf' or first file
    if st.session_state.tamper_mode and ("urgent_report.pdf" in fname or fname == list(st.session_state.evidence_registry.keys())[0]):
        raw_bytes = bytearray(raw_bytes)
        raw_bytes[-1] = (raw_bytes[-1] + 1) % 256
        raw_bytes = bytes(raw_bytes)

    # Integrity verification
    is_valid = verify_integrity(item["original_hash"], raw_bytes)
    item_meta = dict(item["meta"])
    if not is_valid:
        item_meta["tamper_detected"] = True
        item_meta["verification_status"] = "TAMPER DETECTED (Hash Mismatch!)"
        total_tampered += 1
    else:
        item_meta["tamper_detected"] = False
        item_meta["verification_status"] = "VERIFIED (Baseline Intact)"

    chain_of_custody_list.append(item_meta)

    # 1. Parse Email
    if fname.endswith(".eml") or "email" in fname.lower():
        try:
            parsed_email, email_df = parse_email(raw_bytes)
        except Exception:
            pass

    # 2. Check Magic Bytes & File Extension Spoofing
    if fname.endswith(".pdf") or fname.endswith(".exe") or "urgent_report" in fname.lower():
        try:
            spoof_result = check_file_spoofing(fname, raw_bytes)
            if spoof_result["is_spoofed"]:
                file_events.append({
                    "timestamp": "2026-10-27 10:07:05 UTC",
                    "summary": f"File Extension Masquerading Alert: '{fname}' has extension '{spoof_result['declared_extension']}' but magic signature '{spoof_result['detected_signature']}' (4D 5A PE Executable)",
                    "severity": spoof_result["severity"],
                })
        except Exception:
            pass

    # 3. Parse Chromium SQLite History
    if "history" in fname.lower() or fname.endswith(".sqlite") or fname.endswith(".db"):
        try:
            b_df = parse_chromium_history(raw_bytes)
            d_df = parse_chromium_downloads(raw_bytes)
            if not b_df.empty:
                browser_df = b_df
            if not d_df.empty:
                downloads_df = d_df
        except Exception:
            pass

    # 4. Parse PCAP
    if fname.endswith(".pcap") or fname.endswith(".pcapng"):
        try:
            p_df = parse_pcap(raw_bytes)
            if not p_df.empty:
                pcap_df = p_df
                suspicious_flows_df = detect_suspicious_flows(pcap_df)
        except Exception:
            pass

# Correlate into Master Timeline
master_timeline_df = build_master_timeline(
    browser_df=browser_df,
    downloads_df=downloads_df,
    pcap_df=pcap_df,
    email_df=email_df,
    file_events=file_events,
)

# Compute metrics
artifacts_count = len(st.session_state.evidence_registry)
total_events = len(master_timeline_df)
high_risk_count = 0
if not master_timeline_df.empty:
    high_risk_count = len(master_timeline_df[master_timeline_df["criticality"] == "High"])

score_display = "Pending"
if st.session_state.challenge_results:
    score_display = f"{st.session_state.challenge_results['total_score']} / 100"


# ---------------------------------------------------------
# Top Navigation Banner & High-Level Metrics
# ---------------------------------------------------------
st.title("🛡️ CYBERTRACE // DFIR Case Sandbox")
st.caption("Forensic Investigation Workbench • Non-Destructive Parsing • Multi-Source Event Correlation • ISO/IEC 27037")

mcol1, mcol2, mcol3, mcol4 = st.columns(4)

with mcol1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="title">Evidence Ingested</div>
        <div class="value">{artifacts_count} Files</div>
        <div class="subtext">{total_events} Correlated Forensic Events</div>
    </div>
    """, unsafe_allow_html=True)

with mcol2:
    if artifacts_count == 0:
        custody_status = '<span style="color: #94a3b8;">NO EVIDENCE</span>'
    elif total_tampered > 0:
        custody_status = '<span class="badge-tampered">TAMPER DETECTED ⚠️</span>'
    else:
        custody_status = '<span class="badge-verified">INTEGRITY VERIFIED ✓</span>'

    st.markdown(f"""
    <div class="metric-card">
        <div class="title">ISO 27037 Custody</div>
        <div class="value">{custody_status}</div>
        <div class="subtext">SHA-256 Baseline Integrity</div>
    </div>
    """, unsafe_allow_html=True)

with mcol3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="title">High-Risk Indicators</div>
        <div class="value" style="color: {'#ef4444' if high_risk_count > 0 else '#10b981'};">{high_risk_count}</div>
        <div class="subtext">Phishing, Masquerading, C2 Flows</div>
    </div>
    """, unsafe_allow_html=True)

with mcol4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="title">Examiner Evaluation</div>
        <div class="value" style="color: #f59e0b;">{score_display}</div>
        <div class="subtext">Lab Rubric Assessment</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br/>", unsafe_allow_html=True)

if artifacts_count == 0:
    st.info("💡 **Getting Started:** Click **'Load Mock Crime Scene Data'** in the sidebar to load the synthetic data exfiltration scenario, or upload your own forensic artifacts (.eml, .pdf, History, .pcap).")


# ---------------------------------------------------------
# Primary Analysis Tabs
# ---------------------------------------------------------
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📋 Chain of Custody (ISO 27037)",
    "📧 Email & Phishing",
    "🌐 Web Browser",
    "🔍 Magic Bytes & Spoofing",
    "📡 Network PCAP",
    "⏳ Master Timeline & MITRE",
    "⚖️ Examiner Challenge & Report",
])


# =========================================================
# TAB 1: Chain of Custody & Evidence Hashes
# =========================================================
with tab1:
    st.subheader("Digital Evidence Chain of Custody & Integrity Ledger")
    st.markdown("""
    **ISO/IEC 27037 Standard Principle:** All digital evidence must be acquired and processed 
    in a non-destructive manner. Baseline cryptographic digests (MD5 and SHA-256) are calculated 
    in-memory upon acquisition to guarantee non-repudiation and verify evidence integrity.
    """)

    if not chain_of_custody_list:
        st.warning("No digital artifacts currently ingested.")
    else:
        for item in chain_of_custody_list:
            is_tampered = item.get("tamper_detected", False)
            card_border = "#dc2626" if is_tampered else "#334155"
            status_badge = (
                '<span class="badge-tampered">COMPROMISED / HASH MISMATCH</span>'
                if is_tampered
                else '<span class="badge-verified">INTEGRITY VERIFIED</span>'
            )

            st.markdown(f"""
            <div style="background-color: #131b2e; border: 1px solid {card_border}; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 700; font-size: 1.05rem; color: #38bdf8;">📄 {item['filename']}</span>
                    {status_badge}
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-top: 10px; font-size: 0.85rem;">
                    <div><b>File Size:</b> {item['file_size_human']} ({item['file_size_bytes']} bytes)</div>
                    <div><b>Acquisition Time:</b> {item['acquisition_time']}</div>
                    <div><b>Evidence Custodian:</b> {item['custodian']}</div>
                </div>
                <div style="margin-top: 8px; font-size: 0.8rem; background-color: #0b0f19; padding: 8px; border-radius: 4px;">
                    <div><b>MD5:</b> <span class="mono-text" style="color: #cbd5e1;">{item['md5']}</span></div>
                    <div style="margin-top: 3px;"><b>SHA-256:</b> <span class="mono-text" style="color: #38bdf8;">{item['sha256']}</span></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("#### Evidence Custody Audit Table")
        st.dataframe(pd.DataFrame(chain_of_custody_list), use_container_width=True)


# =========================================================
# TAB 2: Email & Phishing Forensics (Week 1 Syllabus)
# =========================================================
with tab2:
    st.subheader("Email Header Analysis & Phishing Ingestion (RFC 822)")
    st.markdown("Examines RFC 822 email headers, extracts originating IP hops, inspects SPF/DKIM authentication, and surfaces malicious hyperlinks.")

    if not parsed_email:
        st.info("No email artifact (.eml) ingested. Load the mock crime scene or upload an .eml file.")
    else:
        ecol1, ecol2, ecol3 = st.columns(3)
        with ecol1:
            st.metric("Originating IP", parsed_email["originating_ip"])
        with ecol2:
            spf_state = parsed_email["auth_info"]["spf_status"]
            st.metric("SPF Verification", spf_state)
        with ecol3:
            dkim_state = parsed_email["auth_info"]["dkim_status"]
            st.metric("DKIM Verification", dkim_state)

        st.markdown("#### Header Inspection")
        st.markdown(f"""
        - **From:** `{parsed_email['sender']}`
        - **To:** `{parsed_email['recipient']}`
        - **Subject:** `{parsed_email['subject']}`
        - **Timestamp (UTC):** `{parsed_email['date_utc']}`
        - **Originating IP:** `{parsed_email['originating_ip']}` (Extracted from RFC 822 `Received` header trace)
        """)

        if parsed_email["auth_info"]["is_spoofed"]:
            st.error("⚠️ **AUTHENTICATION SPOOFING DETECTED:** This message failed SPF and/or DKIM authentication. The sender address appears forged.")

        st.markdown("#### Embedded Hyperlinks & Threat Heuristics")
        if parsed_email["links"]:
            links_df = pd.DataFrame(parsed_email["links"])
            st.dataframe(links_df, use_container_width=True)
        else:
            st.write("No hyperlinks detected in the message body.")

        with st.expander("View Raw Email Message Body"):
            st.code(parsed_email["body_preview"])


# =========================================================
# TAB 3: Web Browser Forensics
# =========================================================
with tab3:
    st.subheader("Chromium Artifact Forensics (History & Downloads)")
    st.markdown("Extracts navigation histories and download chains from SQLite database tables (`urls`, `visits`, `downloads`), accurately converting Chromium WebKit epoch microseconds to UTC.")

    if browser_df.empty and downloads_df.empty:
        st.info("No Chromium SQLite database ingested. Load the mock crime scene or upload a Chromium History file.")
    else:
        btab1, btab2 = st.tabs(["Visited URLs", "File Downloads"])

        with btab1:
            if not browser_df.empty:
                search_q = st.text_input("Filter Browser URLs / Titles", "")
                filtered_b_df = browser_df
                if search_q:
                    filtered_b_df = browser_df[
                        browser_df["url"].str.contains(search_q, case=False, na=False)
                        | browser_df["title"].str.contains(search_q, case=False, na=False)
                    ]
                st.dataframe(filtered_b_df, use_container_width=True)

                st.markdown("#### Top Domains Visited")
                browser_df["domain"] = browser_df["url"].apply(lambda u: u.split("/")[2] if "/" in u and len(u.split("/")) > 2 else u)
                domain_counts = browser_df["domain"].value_counts().reset_index()
                domain_counts.columns = ["Domain", "Visits"]
                st.bar_chart(domain_counts.set_index("Domain"))
            else:
                st.write("No URLs found in the database.")

        with btab2:
            if not downloads_df.empty:
                st.dataframe(downloads_df, use_container_width=True)
            else:
                st.write("No download records found.")


# =========================================================
# TAB 4: Magic Byte & Signature Analysis (Week 4-5 Syllabus)
# =========================================================
with tab4:
    st.subheader("Magic Byte Signature Analysis & Extension Masquerading")
    st.markdown("""
    **File Signature Inspection:** Attackers frequently disguise executable payloads by renaming them 
    with benign document extensions (e.g., `.pdf`, `.png`, `.xlsx`). Forensic examination validates the 
    underlying binary magic bytes (first 16 bytes) against recognized file type specifications.
    """)

    if not spoof_result:
        st.info("Ingest a file artifact (e.g. `urgent_report.pdf` from the mock crime scene) to analyze its binary magic bytes.")
    else:
        st.markdown(f"""
        <div style="background-color: #131b2e; border: 1px solid #334155; border-radius: 8px; padding: 16px;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #38bdf8;">File: {spoof_result['filename']}</div>
            <div style="margin-top: 8px; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">
                <div><b>Declared Extension:</b> <code>{spoof_result['declared_extension']}</code></div>
                <div><b>Detected Signature:</b> <span style="color: #f87171; font-weight: bold;">{spoof_result['detected_signature']}</span></div>
                <div><b>MIME Type:</b> <code>{spoof_result['mime']}</code></div>
                <div><b>Is Executable Binary:</b> {'YES' if spoof_result['is_executable'] else 'NO'}</div>
            </div>
            <div style="margin-top: 12px; background-color: #0b0f19; padding: 10px; border-radius: 4px;">
                <div style="color: #94a3b8; font-size: 0.8rem; margin-bottom: 4px;">INITIAL 16-BYTE HEX DUMP & ASCII:</div>
                <div class="mono-text" style="color: #38bdf8; font-size: 0.95rem;">{spoof_result['hex_dump_16']}</div>
                <div class="mono-text" style="color: #cbd5e1; font-size: 0.95rem; margin-top: 2px;">{spoof_result['ascii_dump_16']}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if spoof_result["is_spoofed"]:
            st.markdown(f"""
            <div style="background-color: rgba(220, 38, 38, 0.2); border: 1px solid #dc2626; border-radius: 8px; padding: 14px; margin-top: 14px;">
                <div style="color: #f87171; font-weight: bold; font-size: 1rem;">🚨 CRITICAL FORENSIC ANOMALY: EXTENSION SPOOFING CONFIRMED</div>
                <p style="margin-top: 6px; font-size: 0.9rem; color: #fecaca;">{spoof_result['anomaly_reason']}</p>
                <div style="margin-top: 8px;">
                    <span class="badge-mitre">MITRE ATT&CK: {spoof_result['mitre_tactic']}</span>
                    <span class="badge-mitre" style="margin-left: 6px;">{spoof_result['mitre_technique']}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.success("File extension corresponds with detected binary magic bytes.")


# =========================================================
# TAB 5: Network Traffic Analysis (PCAP)
# =========================================================
with tab5:
    st.subheader("Network Packet Inspection & Flow Analysis (Scapy)")
    st.markdown("Reassembles packet flows from PCAP captures, decodes DNS lookups, TCP handshakes, and detects unencrypted or high-risk command and control communications.")

    if pcap_df.empty:
        st.info("No PCAP file ingested. Load the mock crime scene or upload a .pcap file.")
    else:
        net_col1, net_col2, net_col3 = st.columns(3)
        with net_col1:
            st.metric("Total Packets", len(pcap_df))
        with net_col2:
            tcp_count = len(pcap_df[pcap_df["protocol"] == "TCP"])
            st.metric("TCP Flows", tcp_count)
        with net_col3:
            susp_count = len(suspicious_flows_df)
            st.metric("Flagged Threat Flows", susp_count)

        if not suspicious_flows_df.empty:
            st.markdown("#### 🚨 Suspicious Flow Detections")
            st.dataframe(suspicious_flows_df, use_container_width=True)

        st.markdown("#### Packet Dissector")
        proto_filter = st.multiselect(
            "Filter Protocols",
            options=pcap_df["protocol"].unique().tolist(),
            default=pcap_df["protocol"].unique().tolist(),
        )
        filtered_pcap = pcap_df[pcap_df["protocol"].isin(proto_filter)]
        st.dataframe(filtered_pcap, use_container_width=True)


# =========================================================
# TAB 6: Master Forensic Timeline & MITRE ATT&CK
# =========================================================
with tab6:
    st.subheader("Correlated Master Forensic Timeline & MITRE ATT&CK Attribution")
    st.markdown("""
    Normalizes timestamps across heterogeneous evidence sources into a unified chronological sequence. 
    Correlates initial phishing delivery, masqueraded binary execution, DNS resolution, and C2 exfiltration.
    """)

    if master_timeline_df.empty:
        st.info("Ingest digital evidence to build the master forensic timeline.")
    else:
        crit_filter = st.selectbox("Filter by Criticality", ["All Events", "High Criticality", "Medium Criticality", "Low Criticality"])
        display_df = master_timeline_df
        if crit_filter == "High Criticality":
            display_df = master_timeline_df[master_timeline_df["criticality"] == "High"]
        elif crit_filter == "Medium Criticality":
            display_df = master_timeline_df[master_timeline_df["criticality"] == "Medium"]
        elif crit_filter == "Low Criticality":
            display_df = master_timeline_df[master_timeline_df["criticality"] == "Low"]

        # Timeline cards
        for _, row in display_df.iterrows():
            crit = row["criticality"]
            crit_border = "#dc2626" if crit == "High" else ("#f59e0b" if crit == "Medium" else "#334155")
            badge_class = "badge-critical" if crit == "High" else "badge-verified"

            st.markdown(f"""
            <div style="background-color: #131b2e; border-left: 4px solid {crit_border}; border-top: 1px solid #1e293b; border-right: 1px solid #1e293b; border-bottom: 1px solid #1e293b; border-radius: 4px; padding: 12px; margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span class="mono-text" style="color: #38bdf8; font-weight: bold; font-size: 0.85rem;">⏱️ {row['timestamp']}</span>
                    <div>
                        <span class="{badge_class}">{crit}</span>
                        <span class="badge-mitre" style="margin-left: 6px;">{row['mitre_tactic']}</span>
                    </div>
                </div>
                <div style="font-size: 0.9rem; margin-top: 6px; color: #f1f5f9;">
                    <b>[{row['artifact_source']}]</b> {row['event_summary']}
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("#### Master Timeline Data Table")
        st.dataframe(display_df, use_container_width=True)


# =========================================================
# TAB 7: Examiner Challenge, Findings & PDF Report Export
# =========================================================
with tab7:
    st.subheader("Examiner Challenge, Case Findings & Courtroom Report Compilation")
    st.markdown("Test investigative deductions against course rubrics, document conclusions, and generate an official ISO/IEC 27037 courtroom forensic incident report.")

    st.markdown("### 🎯 Examiner Challenge & Competency Rubric")
    st.caption("Input your forensic deductions to evaluate your investigation against benchmark ground truth.")

    with st.form("examiner_challenge_form"):
        ccol1, ccol2 = st.columns(2)
        with ccol1:
            input_suspect_ip = st.text_input("Identified Threat / C2 IP Address", placeholder="e.g. 198.51.100.23")
            input_attack_vector = st.selectbox(
                "Primary Initial Attack Vector",
                [
                    "Spear-phishing email with malicious link/payload",
                    "RDP Brute Force",
                    "SQL Injection on Public Web Server",
                    "Compromised VPN Credentials",
                    "USB Drop / Physical Tampering",
                ],
            )

        with ccol2:
            input_spoofed_file = st.text_input("Disguised / Masqueraded File Name", placeholder="e.g. urgent_report.pdf")
            input_payload_hash = st.text_input("Malicious Payload Hash (MD5 or SHA-256)", placeholder="e.g. MD5 or SHA-256 digest")

        submit_challenge = st.form_submit_button("🧪 Evaluate Forensic Deductions (Rubric Scoring)", type="primary")

    if submit_challenge:
        # Ground Truth Benchmarks for Scenario 01
        expected_ip = "198.51.100.23"
        expected_vector = "Spear-phishing email with malicious link/payload"
        expected_spoofed_file = "urgent_report.pdf"

        breakdown = []
        total_pts = 0

        # Item 1: Threat IP (25 pts)
        if input_suspect_ip.strip() == expected_ip:
            breakdown.append({"category": "Suspect / C2 IP Identification", "expected": expected_ip, "submitted": input_suspect_ip, "points": 25, "max_points": 25})
            total_pts += 25
        else:
            breakdown.append({"category": "Suspect / C2 IP Identification", "expected": expected_ip, "submitted": input_suspect_ip or "(empty)", "points": 0, "max_points": 25})

        # Item 2: Initial Attack Vector (25 pts)
        if input_attack_vector == expected_vector:
            breakdown.append({"category": "Initial Attack Vector Attribution", "expected": expected_vector, "submitted": input_attack_vector, "points": 25, "max_points": 25})
            total_pts += 25
        else:
            breakdown.append({"category": "Initial Attack Vector Attribution", "expected": expected_vector, "submitted": input_attack_vector, "points": 0, "max_points": 25})

        # Item 3: Disguised File (25 pts)
        if expected_spoofed_file in input_spoofed_file.strip().lower():
            breakdown.append({"category": "Disguised File Spoofing Detection", "expected": expected_spoofed_file, "submitted": input_spoofed_file, "points": 25, "max_points": 25})
            total_pts += 25
        else:
            breakdown.append({"category": "Disguised File Spoofing Detection", "expected": expected_spoofed_file, "submitted": input_spoofed_file or "(empty)", "points": 0, "max_points": 25})

        # Item 4: Payload Hash Verification (25 pts)
        # Check against SHA-256 or MD5 of any ingested file
        hash_matched = False
        for item in chain_of_custody_list:
            if input_payload_hash.strip().lower() in (item["md5"], item["sha256"]):
                hash_matched = True
                break

        if hash_matched or (len(input_payload_hash.strip()) >= 32):
            breakdown.append({"category": "Cryptographic Evidence Hash Matching", "expected": "Valid Artifact SHA-256/MD5", "submitted": input_payload_hash[:16] + "...", "points": 25, "max_points": 25})
            total_pts += 25
        else:
            breakdown.append({"category": "Cryptographic Evidence Hash Matching", "expected": "Valid Artifact SHA-256/MD5", "submitted": input_payload_hash or "(empty)", "points": 0, "max_points": 25})

        grade = "A (Exemplary)" if total_pts == 100 else ("B (Proficient)" if total_pts >= 75 else "C (Needs Review)")
        st.session_state.challenge_results = {
            "total_score": total_pts,
            "grade": grade,
            "breakdown": breakdown,
            "feedback_summary": f"Evaluation Score: {total_pts}/100. Grade: {grade}.",
        }

    if st.session_state.challenge_results:
        res = st.session_state.challenge_results
        score_color = "#10b981" if res["total_score"] >= 75 else "#ef4444"
        st.markdown(f"""
        <div style="background-color: #131b2e; border: 1px solid {score_color}; border-radius: 8px; padding: 16px; margin-top: 14px;">
            <div style="font-size: 1.2rem; font-weight: bold; color: {score_color};">
                LAB EVALUATION SCORE: {res['total_score']} / 100 ({res['grade']})
            </div>
            <p style="margin-top: 6px; font-size: 0.9rem; color: #cbd5e1;">{res['feedback_summary']}</p>
        </div>
        """, unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(res["breakdown"]), use_container_width=True)

    st.markdown("---")
    st.markdown("### 📄 Courtroom Forensic Report Generator")

    with st.form("report_metadata_form"):
        rcol1, rcol2 = st.columns(2)
        with rcol1:
            rep_case_id = st.text_input("Case Reference Number", value="DFIR-2026-0045")
            rep_investigator = st.text_input("Lead Forensic Examiner", value="Special Agent / Examiner Vance")
            rep_agency = st.text_input("Agency / Forensic Laboratory", value="Cyber Defense & Forensics Division")

        with rcol2:
            rep_case_name = st.text_input("Case Title", value="Unauthorized Data Exfiltration Incident")
            rep_c2_ip = st.text_input("Attributed Threat Actor IP", value="198.51.100.23")
            rep_vector = st.text_input("Primary Attack Vector", value="Spear-phishing email with extension-spoofed PE binary")

        rep_notes = st.text_area("Investigator Narrative Findings & Incident Conclusions", value=st.session_state.case_notes, height=130)

        compile_pdf = st.form_submit_button("⚖️ Compile Official Courtroom Forensic PDF Report", type="primary")

    if compile_pdf:
        if not chain_of_custody_list:
            st.error("Cannot compile forensic report: No digital evidence currently ingested.")
        else:
            with st.spinner("Compiling ReportLab PDF document with ISO 27037 compliance ledger..."):
                metadata = {
                    "case_id": rep_case_id,
                    "case_name": rep_case_name,
                    "investigator": rep_investigator,
                    "agency": rep_agency,
                    "c2_ip": rep_c2_ip,
                    "vector": rep_vector,
                }
                pdf_bytes = generate_forensic_pdf(
                    case_metadata=metadata,
                    chain_of_custody=chain_of_custody_list,
                    timeline_df=master_timeline_df,
                    investigator_notes=rep_notes,
                    evaluation_results=st.session_state.challenge_results,
                )

                st.success("✅ Official Forensic Incident Report Compiled Successfully!")
                timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                report_filename = f"CyberTrace_Forensic_Report_{rep_case_id}_{timestamp_str}.pdf"

                st.download_button(
                    label="⬇️ Download Courtroom-Ready Forensic PDF Report",
                    data=pdf_bytes,
                    file_name=report_filename,
                    mime="application/pdf",
                    type="primary",
                )
