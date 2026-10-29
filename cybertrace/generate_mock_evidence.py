"""
Synthetic Crime Scene Evidence Generator (DFIR Laboratory Sandbox)
Creates a realistic, multi-artifact forensic scenario:
"Scenario 01: Unauthorized Corporate Data Exfiltration"
Generates:
  1. mock_case/phishing_email.eml (RFC 822 email with failed SPF/DKIM & phishing link)
  2. mock_case/urgent_report.pdf (Spoofed PE binary disguised with .pdf extension)
  3. mock_case/History (Chromium SQLite database with intranet searches & payload download)
  4. mock_case/network_capture.pcap (Scapy trace with DNS lookups, TCP handshakes, port 4444 C2 exfil)
"""

import os
import sqlite3
from datetime import datetime, timezone
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap


def ensure_directory(dir_path: str):
    """Ensures target directory exists."""
    os.makedirs(dir_path, exist_ok=True)


def unix_to_webkit_microseconds(unix_timestamp: float) -> int:
    """Converts a Unix epoch timestamp in seconds to Chromium WebKit microseconds."""
    return int((unix_timestamp + 11_644_473_600.0) * 1_000_000)


def generate_phishing_email(output_path: str):
    """Generates a synthetic RFC 822 phishing email (.eml)."""
    eml_content = (
        "Delivered-To: victim@corp.local\r\n"
        "Received: by mx.corp.local (PostFix) with ESMTP id 8F10A29B\r\n"
        "\tfor <victim@corp.local>; Tue, 27 Oct 2026 10:05:12 +0000 (UTC)\r\n"
        "Received: from mail.secure-update-verify.com ([198.51.100.23])\r\n"
        "\tby mx.corp.local with ESMTP id B7882C40\r\n"
        "\tfor <victim@corp.local>; Tue, 27 Oct 2026 10:05:08 +0000 (UTC)\r\n"
        "Received-SPF: fail (domain of secure-update-verify.com does not designate 198.51.100.23 as permitted sender)\r\n"
        "Authentication-Results: mx.corp.local; spf=fail (sender IP 198.51.100.23); dkim=fail (bad signature)\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=secure-update-verify.com; s=k1;\r\n"
        "\th=from:to:subject:date;\r\n"
        "\tbh=invalid_signature_hash_xyz==; b=forged_signature_bytes_123==\r\n"
        "From: Corporate IT Helpdesk <admin-support@secure-update-verify.com>\r\n"
        "To: Victim Employee <victim@corp.local>\r\n"
        "Subject: URGENT: Mandatory Security Patch & Action Required\r\n"
        "Date: Tue, 27 Oct 2026 10:05:00 +0000\r\n"
        "Message-ID: <20261027100500.8921@secure-update-verify.com>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html>\r\n"
        "<body>\r\n"
        "<h2>URGENT: Corporate Security Notification</h2>\r\n"
        "<p>Dear Employee,</p>\r\n"
        "<p>Our internal security monitors detected unauthorized access attempts on your workstation. "
        "You are required to review the attached incident briefing and install the mandatory update immediately:</p>\r\n"
        "<p><a href=\"http://secure-update-verify.com/download/urgent_report.pdf\">Download Incident Briefing (urgent_report.pdf)</a></p>\r\n"
        "<p>Failure to comply within 24 hours will result in directory account suspension.</p>\r\n"
        "<br/>\r\n"
        "<p>IT Incident Response Team<br/>Global Cyber Operations</p>\r\n"
        "</body>\r\n"
        "</html>\r\n"
    )
    with open(output_path, "wb") as f:
        f.write(eml_content.encode("utf-8"))


def generate_spoofed_pdf(output_path: str):
    """
    Generates a spoofed file: declared as 'urgent_report.pdf' but starting with
    the Windows PE executable signature '4D 5A' ('MZ') to simulate extension masquerading.
    """
    # Standard DOS Header with MZ signature
    dos_header = bytearray(b"\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00")
    dos_header.extend(b"\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00")
    dos_header.extend(b"\x00" * 32)
    # DOS stub string
    dos_stub = (
        b"This program cannot be run in DOS mode.\r\r\n$        "
        b"[CYBERTRACE_SIMULATED_MALWARE_PAYLOAD]"
        b" TARGET_C2=198.51.100.23:4444 EXFIL_TARGET=q4_projections.xlsx"
    )
    payload = dos_header + dos_stub + (b"\x90" * 1024)

    with open(output_path, "wb") as f:
        f.write(payload)


def generate_chromium_history(output_path: str):
    """
    Generates a synthetic SQLite 'History' database with genuine Chromium table structures
    ('urls', 'visits', 'downloads').
    """
    if os.path.exists(output_path):
        os.unlink(output_path)

    conn = sqlite3.connect(output_path)
    cur = conn.cursor()

    # Create Chromium urls table
    cur.execute("""
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url LONGVARCHAR,
            title LONGVARCHAR,
            visit_count INTEGER DEFAULT 0 NOT NULL,
            typed_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL,
            hidden INTEGER DEFAULT 0 NOT NULL
        )
    """)

    # Create visits table
    cur.execute("""
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER,
            transition INTEGER DEFAULT 0 NOT NULL,
            segment_id INTEGER,
            visit_duration INTEGER DEFAULT 0 NOT NULL
        )
    """)

    # Create downloads table
    cur.execute("""
        CREATE TABLE downloads (
            id INTEGER PRIMARY KEY,
            current_path LONGVARCHAR NOT NULL,
            target_path LONGVARCHAR NOT NULL,
            start_time INTEGER NOT NULL,
            received_bytes INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            state INTEGER NOT NULL,
            danger_type INTEGER NOT NULL,
            interrupt_reason INTEGER NOT NULL
        )
    """)

    # Base timestamps: 2026-10-27 10:00:00 UTC = 1793095200 Unix epoch
    base_epoch = 1793095200.0

    browsing_events = [
        (
            "http://intranet.corp.local/dashboard",
            "Corporate Intranet Portal - Home",
            12,
            base_epoch + 120, # 10:02:00
        ),
        (
            "http://intranet.corp.local/search?q=financial_projections_q4",
            "Search Results: financial_projections_q4",
            3,
            base_epoch + 240, # 10:04:00
        ),
        (
            "http://intranet.corp.local/shares/confidential/q4_projections.xlsx",
            "Confidential Q4 Financial Projections.xlsx - Viewer",
            1,
            base_epoch + 330, # 10:05:30
        ),
        (
            "http://secure-update-verify.com/download/urgent_report.pdf",
            "Security Update Download - Action Required",
            1,
            base_epoch + 420, # 10:07:00
        ),
        (
            "http://malicious-c2-update.com/payloads/exfil_tool.exe",
            "Update Verification Executable Staging",
            1,
            base_epoch + 510, # 10:08:30
        ),
    ]

    for url, title, count, epoch_time in browsing_events:
        webkit_time = unix_to_webkit_microseconds(epoch_time)
        cur.execute(
            "INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time) VALUES (?, ?, ?, 0, ?)",
            (url, title, count, webkit_time),
        )
        url_id = cur.lastrowid
        cur.execute(
            "INSERT INTO visits (url, visit_time, transition) VALUES (?, ?, 0)",
            (url_id, webkit_time),
        )

    # Downloads
    downloads = [
        (
            r"C:\Users\Victim\Downloads\urgent_report.pdf",
            r"C:\Users\Victim\Downloads\urgent_report.pdf",
            unix_to_webkit_microseconds(base_epoch + 425),
            1112,
            1112,
            1, # Complete
        ),
        (
            r"C:\Users\Victim\Downloads\exfil_tool.exe",
            r"C:\Users\Victim\Downloads\exfil_tool.exe",
            unix_to_webkit_microseconds(base_epoch + 515),
            524288,
            524288,
            1, # Complete
        ),
    ]

    for cpath, tpath, stime, rec, tot, state in downloads:
        cur.execute(
            "INSERT INTO downloads (current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type, interrupt_reason) VALUES (?, ?, ?, ?, ?, ?, 0, 0)",
            (cpath, tpath, stime, rec, tot, state),
        )

    conn.commit()
    conn.close()


def generate_network_pcap(output_path: str):
    """
    Generates a realistic synthetic network packet capture (.pcap) using Scapy:
      - DNS queries & responses for phishing domain and internal intranet
      - TCP handshake & HTTP GET for payload
      - TCP reverse shell on port 4444 beaconing & exfiltrating data chunks
    """
    packets = []
    base_epoch = 1793095200.0 + 400.0 # ~ 10:06:40 UTC

    workstation_ip = "192.168.1.45"
    dns_server_ip = "8.8.8.8"
    c2_ip = "198.51.100.23"
    workstation_mac = "00:1A:2B:3C:4D:5E"
    router_mac = "AA:BB:CC:DD:EE:FF"

    # 1. DNS Query for secure-update-verify.com
    t1 = base_epoch + 10.0
    p_dns_q = Ether(src=workstation_mac, dst=router_mac) / \
              IP(src=workstation_ip, dst=dns_server_ip) / \
              UDP(sport=53812, dport=53) / \
              DNS(rd=1, qd=DNSQR(qname="secure-update-verify.com"))
    p_dns_q.time = t1
    packets.append(p_dns_q)

    # 2. DNS Response returning C2 IP
    t2 = t1 + 0.05
    p_dns_r = Ether(src=router_mac, dst=workstation_mac) / \
              IP(src=dns_server_ip, dst=workstation_ip) / \
              UDP(sport=53, dport=53812) / \
              DNS(qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname="secure-update-verify.com"),
                  an=DNSRR(rrname="secure-update-verify.com", rdata=c2_ip, ttl=300))
    p_dns_r.time = t2
    packets.append(p_dns_r)

    # 3. TCP Handshake to C2 Server port 80 (HTTP download)
    t3 = t2 + 0.1
    p_syn = Ether(src=workstation_mac, dst=router_mac) / \
            IP(src=workstation_ip, dst=c2_ip) / \
            TCP(sport=49821, dport=80, flags="S", seq=1000)
    p_syn.time = t3
    packets.append(p_syn)

    t4 = t3 + 0.03
    p_synack = Ether(src=router_mac, dst=workstation_mac) / \
               IP(src=c2_ip, dst=workstation_ip) / \
               TCP(sport=80, dport=49821, flags="SA", seq=5000, ack=1001)
    p_synack.time = t4
    packets.append(p_synack)

    t5 = t4 + 0.01
    p_ack = Ether(src=workstation_mac, dst=router_mac) / \
            IP(src=workstation_ip, dst=c2_ip) / \
            TCP(sport=49821, dport=80, flags="A", seq=1001, ack=5001)
    p_ack.time = t5
    packets.append(p_ack)

    # 4. HTTP GET request for the spoofed payload
    t6 = t5 + 0.02
    http_payload = "GET /download/urgent_report.pdf HTTP/1.1\r\nHost: secure-update-verify.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    p_http_req = Ether(src=workstation_mac, dst=router_mac) / \
                 IP(src=workstation_ip, dst=c2_ip) / \
                 TCP(sport=49821, dport=80, flags="PA", seq=1001, ack=5001) / \
                 Raw(load=http_payload.encode())
    p_http_req.time = t6
    packets.append(p_http_req)

    # 5. HTTP Response
    t7 = t6 + 0.05
    http_resp = "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: 1112\r\n\r\nMZ\x90\x00..."
    p_http_res = Ether(src=router_mac, dst=workstation_mac) / \
                 IP(src=c2_ip, dst=workstation_ip) / \
                 TCP(sport=80, dport=49821, flags="PA", seq=5001, ack=1001 + len(http_payload)) / \
                 Raw(load=http_resp.encode())
    p_http_res.time = t7
    packets.append(p_http_res)

    # 6. C2 Reverse Shell Connection to Port 4444 (CRITICAL / MITRE T1041 / T1571)
    t8 = t7 + 85.0 # ~ 10:08:15 UTC
    p_c2_syn = Ether(src=workstation_mac, dst=router_mac) / \
               IP(src=workstation_ip, dst=c2_ip) / \
               TCP(sport=51234, dport=4444, flags="S", seq=20000)
    p_c2_syn.time = t8
    packets.append(p_c2_syn)

    t9 = t8 + 0.04
    p_c2_synack = Ether(src=router_mac, dst=workstation_mac) / \
                  IP(src=c2_ip, dst=workstation_ip) / \
                  TCP(sport=4444, dport=51234, flags="SA", seq=70000, ack=20001)
    p_c2_synack.time = t9
    packets.append(p_c2_synack)

    t10 = t9 + 0.01
    p_c2_ack = Ether(src=workstation_mac, dst=router_mac) / \
               IP(src=workstation_ip, dst=c2_ip) / \
               TCP(sport=51234, dport=4444, flags="A", seq=20001, ack=70001)
    p_c2_ack.time = t10
    packets.append(p_c2_ack)

    # 7. Exfiltrated Payload chunk transmitted to C2 Port 4444
    t11 = t10 + 0.05
    exfil_data = (
        b"[CYBERTRACE_C2_BEACON] WORKSTATION=DESKTOP-FIN04 HOST=192.168.1.45 "
        b"STATUS=EXFILTRATING PAYLOAD_SRC=q4_projections.xlsx PAYLOAD_BYTES=45056 "
        b"CIPHER=AES-256-CBC HASH=8a7c29e1f409..."
    )
    p_exfil = Ether(src=workstation_mac, dst=router_mac) / \
              IP(src=workstation_ip, dst=c2_ip) / \
              TCP(sport=51234, dport=4444, flags="PA", seq=20001, ack=70001) / \
              Raw(load=exfil_data)
    p_exfil.time = t11
    packets.append(p_exfil)

    # 8. C2 ACK and Teardown
    t12 = t11 + 0.03
    p_c2_ack2 = Ether(src=router_mac, dst=workstation_mac) / \
                IP(src=c2_ip, dst=workstation_ip) / \
                TCP(sport=4444, dport=51234, flags="A", seq=70001, ack=20001 + len(exfil_data))
    p_c2_ack2.time = t12
    packets.append(p_c2_ack2)

    wrpcap(output_path, packets)


def build_mock_case(target_dir: str = "./mock_case") -> dict:
    """
    Generates all 4 synthetic evidence artifacts inside target_dir.
    Returns dictionary with filepaths.
    """
    ensure_directory(target_dir)

    email_path = os.path.join(target_dir, "phishing_email.eml")
    pdf_path = os.path.join(target_dir, "urgent_report.pdf")
    history_path = os.path.join(target_dir, "History")
    pcap_path = os.path.join(target_dir, "network_capture.pcap")

    generate_phishing_email(email_path)
    generate_spoofed_pdf(pdf_path)
    generate_chromium_history(history_path)
    generate_network_pcap(pcap_path)

    return {
        "email": email_path,
        "spoofed_pdf": pdf_path,
        "history": history_path,
        "pcap": pcap_path,
    }


if __name__ == "__main__":
    print("[*] Generating CyberTrace mock forensic crime scene...")
    paths = build_mock_case()
    print("[+] Synthetic crime scene successfully created in ./mock_case/:")
    for k, v in paths.items():
        print(f"    - {k}: {v} ({os.path.getsize(v)} bytes)")
