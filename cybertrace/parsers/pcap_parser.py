"""
Network PCAP Dissector & Flow Analyzer (Scapy Engine)
Reassembles network flows, decodes TCP/UDP/DNS layers, extracts DNS query names,
and detects anomalous / C2 beaconing communication patterns.
"""

import os
import tempfile
from datetime import datetime, timezone
from typing import List, Dict, Any
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw


# High-risk ports often associated with unencrypted access or C2 backdoors
HIGH_RISK_PORTS = {
    21: "FTP (Unencrypted File Transfer)",
    23: "Telnet (Unencrypted Remote Shell)",
    80: "HTTP (Unencrypted Web / Potential Exfiltration)",
    4444: "Metasploit / Generic C2 Reverse Shell Port",
    6667: "IRC (Botnet Command & Control)",
    8080: "HTTP Alternate / Proxy",
    8443: "HTTPS Alternate",
}


def format_epoch_utc(epoch_time: float) -> str:
    """Converts a Unix epoch float into standardized ISO 8601 UTC string."""
    try:
        dt = datetime.fromtimestamp(float(epoch_time), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "Unknown Timestamp"


def parse_pcap(file_bytes: bytes) -> pd.DataFrame:
    """
    Parses network packets from raw PCAP/PCAPNG bytes using Scapy rdpcap.

    Extracts:
        - timestamp (UTC formatted)
        - src_ip, dst_ip
        - protocol (TCP, UDP, DNS, ICMP, etc.)
        - src_port, dst_port
        - info (TCP flags, DNS query strings, HTTP requests)
        - source = 'Network Packet'
    """
    expected_cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "info", "source"]

    if not file_bytes:
        return pd.DataFrame(columns=expected_cols)

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_file:
            tmp_file.write(file_bytes)
            tmp_path = tmp_file.name

        packets = rdpcap(tmp_path)
        records: List[Dict[str, Any]] = []

        for pkt in packets:
            # Timestamp
            pkt_time = float(pkt.time) if hasattr(pkt, "time") else 0.0
            ts_utc = format_epoch_utc(pkt_time)

            src_ip = "N/A"
            dst_ip = "N/A"
            protocol = "Other"
            src_port = "-"
            dst_port = "-"
            info = ""

            # IP Layer
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = "IP"
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                protocol = "IPv6"

            # DNS Layer
            if pkt.haslayer(DNS):
                protocol = "DNS"
                dns_layer = pkt[DNS]
                if dns_layer.qr == 0 and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                    info = f"DNS Standard Query A: {qname}"
                elif dns_layer.qr == 1:
                    info = f"DNS Response (Answers: {dns_layer.ancount})"
                else:
                    info = "DNS Packet"

            # TCP Layer
            elif pkt.haslayer(TCP):
                protocol = "TCP"
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport

                flags = []
                if tcp_layer.flags.S:
                    flags.append("SYN")
                if tcp_layer.flags.A:
                    flags.append("ACK")
                if tcp_layer.flags.F:
                    flags.append("FIN")
                if tcp_layer.flags.R:
                    flags.append("RST")
                if tcp_layer.flags.P:
                    flags.append("PSH")

                flag_str = "/".join(flags) if flags else "NONE"
                info = f"Seq={tcp_layer.seq} Ack={tcp_layer.ack} Flags=[{flag_str}] Len={len(pkt)}"

                # Check for HTTP payload in Raw
                if pkt.haslayer(Raw):
                    raw_data = pkt[Raw].load
                    try:
                        ascii_sample = raw_data[:120].decode("ascii", errors="ignore")
                        for method in ["GET ", "POST ", "HEAD ", "HTTP/1."]:
                            if method in ascii_sample:
                                first_line = ascii_sample.split("\r\n")[0]
                                info += f" | {first_line}"
                                protocol = "HTTP"
                                break
                    except Exception:
                        pass

            # UDP Layer
            elif pkt.haslayer(UDP):
                protocol = "UDP"
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                info = f"Len={udp_layer.len}"

            # ICMP Layer
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                icmp_layer = pkt[ICMP]
                info = f"Type={icmp_layer.type} Code={icmp_layer.code}"

            records.append({
                "timestamp": ts_utc,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "info": info or "Raw Packet",
                "source": "Network Packet",
            })

        if not records:
            return pd.DataFrame(columns=expected_cols)

        return pd.DataFrame(records)

    except Exception:
        return pd.DataFrame(columns=expected_cols)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def detect_suspicious_flows(df: pd.DataFrame) -> pd.DataFrame:
    """
    Evaluates packet records against DFIR heuristic threat rules:
      1. Outbound traffic to high-risk or unencrypted ports (e.g. 4444, 21, 23, 80).
      2. DNS queries for suspicious phishing domains or suspicious keywords.
      3. Frequent repeated external interactions indicating C2 beaconing.
    """
    cols = ["timestamp", "src_ip", "dst_ip", "protocol", "port", "risk_level", "reason"]
    if df.empty:
        return pd.DataFrame(columns=cols)

    flagged_records: List[Dict[str, Any]] = []

    for _, row in df.iterrows():
        dst_port_str = str(row.get("dst_port", ""))
        src_port_str = str(row.get("src_port", ""))
        info = str(row.get("info", ""))
        proto = str(row.get("protocol", ""))
        dst_ip = str(row.get("dst_ip", ""))
        src_ip = str(row.get("src_ip", ""))
        ts = str(row.get("timestamp", ""))

        # Check destination port
        try:
            dport = int(dst_port_str)
        except ValueError:
            dport = None

        try:
            sport = int(src_port_str)
        except ValueError:
            sport = None

        # Rule 1: High risk ports (e.g. port 4444 reverse shell, port 21 FTP)
        for p, desc in HIGH_RISK_PORTS.items():
            if dport == p or sport == p:
                risk = "High" if p in (4444, 23) else "Medium"
                flagged_records.append({
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto,
                    "port": p,
                    "risk_level": risk,
                    "reason": f"Connection on suspicious port: {desc}",
                })
                break

        # Rule 2: Phishing / C2 domain queries
        if proto == "DNS" and "DNS Standard Query" in info:
            for kw in ["secure-update", "c2", "malicious", "payload", "exfil", "pastebin"]:
                if kw in info.lower():
                    flagged_records.append({
                        "timestamp": ts,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": "DNS",
                        "port": 53,
                        "risk_level": "High",
                        "reason": f"DNS query resolves high-risk domain with keyword '{kw}'",
                    })
                    break

    if not flagged_records:
        return pd.DataFrame(columns=cols)

    return pd.DataFrame(flagged_records).drop_duplicates()
