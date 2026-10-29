"""
Master Forensic Timeline & MITRE ATT&CK Correlation Engine
Unifies heterogeneous artifact streams (Email, Browser, Downloads, Magic Bytes, Network PCAP),
normalizes timestamps to UTC, scores event criticality, and attributes MITRE ATT&CK tactics.
"""

from typing import List, Dict, Any, Optional
import pandas as pd


def assess_criticality_and_mitre(source: str, summary: str, details: str = "") -> Dict[str, str]:
    """
    Evaluates event metadata against forensic threat indicators and tags
    corresponding MITRE ATT&CK Tactic and Technique IDs.
    """
    text = f"{summary} {details}".lower()

    # Rule 1: Exfiltration over C2 Channel / Non-Standard Port
    if "4444" in text or "exfil" in text or "beaconing" in text:
        return {
            "criticality": "High",
            "mitre_tactic": "Command & Control / Exfiltration",
            "mitre_technique_id": "T1041 / T1571",
        }

    # Rule 2: File Extension Spoofing / Masquerading
    if "spoof" in text or "masquerad" in text or "disguised" in text or ("pdf" in text and "pe" in text):
        return {
            "criticality": "High",
            "mitre_tactic": "Defense Evasion",
            "mitre_technique_id": "T1036 (Masquerading)",
        }

    # Rule 3: Direct Executable Download / Payload Staging
    if ".exe" in text or ".scr" in text or "payload" in text or "malicious-c2" in text:
        return {
            "criticality": "High",
            "mitre_tactic": "Execution",
            "mitre_technique_id": "T1204 (User Execution)",
        }

    # Rule 4: Phishing Email / Spoofed Domain
    if "phish" in text or "spf: fail" in text or "dkim: fail" in text or "secure-update-verify" in text:
        return {
            "criticality": "High",
            "mitre_tactic": "Initial Access",
            "mitre_technique_id": "T1566 (Phishing)",
        }

    # Rule 5: External HTTP / C2 IP connection
    if "198.51.100." in text or "unencrypted web" in text or "dns query" in text:
        return {
            "criticality": "Medium",
            "mitre_tactic": "Command & Control",
            "mitre_technique_id": "T1071 (App Layer Protocol)",
        }

    # Default internal activity
    return {
        "criticality": "Low",
        "mitre_tactic": "Routine / Discovery",
        "mitre_technique_id": "T1082 / T1087",
    }


def build_master_timeline(
    browser_df: Optional[pd.DataFrame] = None,
    downloads_df: Optional[pd.DataFrame] = None,
    pcap_df: Optional[pd.DataFrame] = None,
    email_df: Optional[pd.DataFrame] = None,
    file_events: Optional[List[Dict[str, Any]]] = None,
) -> pd.DataFrame:
    """
    Correlates multi-source digital artifacts into an authoritative master forensic timeline.

    Returns:
        pd.DataFrame with columns:
        ['timestamp', 'artifact_source', 'event_summary', 'criticality', 'mitre_tactic', 'mitre_technique_id']
    """
    timeline_records: List[Dict[str, Any]] = []

    # 1. Ingest Email Events
    if email_df is not None and not email_df.empty:
        for _, row in email_df.iterrows():
            sender = row.get("sender", "")
            subject = row.get("subject", "")
            orig_ip = row.get("originating_ip", "")
            spf = row.get("spf_status", "")
            summary = f"Phishing Email Received from '{sender}' (Orig IP: {orig_ip}) | Subject: '{subject}' | SPF: {spf}"
            meta = assess_criticality_and_mitre("Email", summary)
            timeline_records.append({
                "timestamp": str(row.get("timestamp", "")),
                "artifact_source": "Email Artifact (.eml)",
                "event_summary": summary,
                "criticality": meta["criticality"],
                "mitre_tactic": meta["mitre_tactic"],
                "mitre_technique_id": meta["mitre_technique_id"],
            })

    # 2. Ingest Browser History Events
    if browser_df is not None and not browser_df.empty:
        for _, row in browser_df.iterrows():
            url = str(row.get("url", ""))
            title = str(row.get("title", ""))
            visits = row.get("visit_count", 1)
            summary = f"Browser Navigation: {url} (Title: '{title}', Visits: {visits})"
            meta = assess_criticality_and_mitre("Browser", summary, url)
            timeline_records.append({
                "timestamp": str(row.get("timestamp", "")),
                "artifact_source": "Browser History",
                "event_summary": summary,
                "criticality": meta["criticality"],
                "mitre_tactic": meta["mitre_tactic"],
                "mitre_technique_id": meta["mitre_technique_id"],
            })

    # 3. Ingest Downloads Events
    if downloads_df is not None and not downloads_df.empty:
        for _, row in downloads_df.iterrows():
            target_path = str(row.get("target_path", ""))
            bytes_rec = row.get("received_bytes", 0)
            state = row.get("state", "Complete")
            summary = f"File Ingestion/Download: '{target_path}' ({bytes_rec} bytes, State: {state})"
            meta = assess_criticality_and_mitre("Downloads", summary, target_path)
            timeline_records.append({
                "timestamp": str(row.get("timestamp", "")),
                "artifact_source": "Browser Downloads",
                "event_summary": summary,
                "criticality": meta["criticality"],
                "mitre_tactic": meta["mitre_tactic"],
                "mitre_technique_id": meta["mitre_technique_id"],
            })

    # 4. Ingest File Spoofing / Magic Byte Events
    if file_events:
        for fe in file_events:
            summary = fe.get("summary", "File Signature Verification")
            ts = fe.get("timestamp", "2026-10-27 10:14:35 UTC")
            meta = assess_criticality_and_mitre("MagicBytes", summary)
            timeline_records.append({
                "timestamp": ts,
                "artifact_source": "File Signature / Magic Bytes",
                "event_summary": summary,
                "criticality": meta["criticality"],
                "mitre_tactic": meta["mitre_tactic"],
                "mitre_technique_id": meta["mitre_technique_id"],
            })

    # 5. Ingest Network PCAP Events
    if pcap_df is not None and not pcap_df.empty:
        # Sample key events (DNS queries, HTTP requests, TCP Handshakes, Port 4444)
        for _, row in pcap_df.iterrows():
            proto = str(row.get("protocol", ""))
            info = str(row.get("info", ""))
            src = str(row.get("src_ip", ""))
            dst = str(row.get("dst_ip", ""))
            dport = str(row.get("dst_port", ""))
            sport = str(row.get("src_port", ""))

            # Filter for key investigative events to avoid flooding the master timeline
            is_key_packet = False
            if proto == "DNS" and "Query" in info:
                is_key_packet = True
            elif proto == "HTTP":
                is_key_packet = True
            elif dport in ("4444", "21", "23") or sport in ("4444", "21", "23"):
                is_key_packet = True
            elif "SYN" in info:
                is_key_packet = True

            if is_key_packet:
                summary = f"Network Packet [{proto}] {src}:{sport} -> {dst}:{dport} | {info}"
                meta = assess_criticality_and_mitre("Network", summary, f"{dport} {dst} {info}")
                timeline_records.append({
                    "timestamp": str(row.get("timestamp", "")),
                    "artifact_source": "Network Packet Capture",
                    "event_summary": summary,
                    "criticality": meta["criticality"],
                    "mitre_tactic": meta["mitre_tactic"],
                    "mitre_technique_id": meta["mitre_technique_id"],
                })

    cols = ["timestamp", "artifact_source", "event_summary", "criticality", "mitre_tactic", "mitre_technique_id"]
    if not timeline_records:
        return pd.DataFrame(columns=cols)

    master_df = pd.DataFrame(timeline_records)

    # Clean timestamps and sort chronologically
    # Normalize valid timestamps for sorting
    master_df["sort_key"] = pd.to_datetime(
        master_df["timestamp"].str.replace(" UTC", "", regex=False),
        errors="coerce"
    )
    master_df = master_df.sort_values(by="sort_key", ascending=True)
    master_df = master_df.drop(columns=["sort_key"]).reset_index(drop=True)

    return master_df
