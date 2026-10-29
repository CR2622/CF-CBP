"""
CyberTrace Automated Forensic Self-Test Suite
Validates all modules:
  - Cryptographic Hasher & Integrity Verification (ISO 27037)
  - Synthetic Mock Evidence Generator
  - RFC 822 Email Parser with SPF/DKIM & Link Threat Detection
  - Magic Byte Signature Analyzer & Extension Spoofing Detector
  - Chromium SQLite History & Downloads Parser
  - Scapy Network PCAP Parser & Suspicious Flow Detector
  - Master Forensic Timeline & MITRE ATT&CK Engine
  - ReportLab Courtroom PDF Report Generation
"""

import os
import sys

# Ensure UTF-8 output on Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add cybertrace to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybertrace"))

from cybertrace.parsers.evidence_hasher import compute_file_hashes, verify_integrity
from cybertrace.parsers.email_parser import parse_email
from cybertrace.parsers.magic_checker import detect_file_signature, check_file_spoofing
from cybertrace.parsers.browser_parser import parse_chromium_history, parse_chromium_downloads
from cybertrace.parsers.pcap_parser import parse_pcap, detect_suspicious_flows
from cybertrace.parsers.timeline_engine import build_master_timeline
from cybertrace.utils.report_generator import generate_forensic_pdf
import cybertrace.generate_mock_evidence as mock_gen


def test_evidence_hasher():
    print("[1/8] Testing evidence_hasher.py...")
    sample_data = b"FORENSIC_EVIDENCE_SAMPLE_BYTES_ISO_27037"
    hashes = compute_file_hashes(sample_data, "sample.bin", custodian="Examiner")
    assert "md5" in hashes and len(hashes["md5"]) == 32
    assert "sha256" in hashes and len(hashes["sha256"]) == 64
    assert hashes["file_size_bytes"] == len(sample_data)

    # Test integrity check (untampered)
    assert verify_integrity(hashes["sha256"], sample_data) is True

    # Test integrity check (tampered)
    tampered_data = b"FORENSIC_EVIDENCE_SAMPLE_BYTES_ISO_27038"
    assert verify_integrity(hashes["sha256"], tampered_data) is False
    print("      [PASS] Hashes computed & tamper detection verified.")


def test_mock_evidence_generation():
    print("[2/8] Testing generate_mock_evidence.py...")
    test_dir = os.path.join(os.path.dirname(__file__), "test_mock_case")
    paths = mock_gen.build_mock_case(test_dir)
    assert os.path.exists(paths["email"])
    assert os.path.exists(paths["spoofed_pdf"])
    assert os.path.exists(paths["history"])
    assert os.path.exists(paths["pcap"])
    print("      [PASS] Generated 4 synthetic crime scene artifacts.")
    return paths


def test_email_parser(eml_path: str):
    print("[3/8] Testing email_parser.py...")
    with open(eml_path, "rb") as f:
        eml_bytes = f.read()

    parsed_dict, df = parse_email(eml_bytes)
    assert "198.51.100.23" in parsed_dict["originating_ip"]
    assert "FAIL" in parsed_dict["auth_info"]["spf_status"]
    assert len(parsed_dict["links"]) > 0
    assert not df.empty
    print("      [PASS] Email parsed: Originating IP, failed SPF/DKIM, and link extracted.")


def test_magic_checker(spoofed_pdf_path: str):
    print("[4/8] Testing magic_checker.py...")
    with open(spoofed_pdf_path, "rb") as f:
        pdf_bytes = f.read()

    spoof_res = check_file_spoofing("urgent_report.pdf", pdf_bytes)
    assert spoof_res["is_spoofed"] is True
    assert spoof_res["severity"] == "CRITICAL"
    assert "4D 5A" in spoof_res["hex_dump_16"]
    assert "PE Executable" in spoof_res["detected_signature"]
    assert "T1036" in spoof_res["mitre_technique"]
    print("      [PASS] Magic checker: Confirmed PE header masquerading as PDF.")


def test_browser_parser(history_path: str):
    print("[5/8] Testing browser_parser.py...")
    with open(history_path, "rb") as f:
        hist_bytes = f.read()

    b_df = parse_chromium_history(hist_bytes)
    d_df = parse_chromium_downloads(hist_bytes)
    assert not b_df.empty
    assert len(b_df) >= 5
    assert not d_df.empty
    assert any("urgent_report.pdf" in p for p in d_df["target_path"])
    print(f"      [PASS] Browser parsed: {len(b_df)} URLs, {len(d_df)} downloads extracted.")
    return b_df, d_df


def test_pcap_parser(pcap_path: str):
    print("[6/8] Testing pcap_parser.py...")
    with open(pcap_path, "rb") as f:
        pcap_bytes = f.read()

    p_df = parse_pcap(pcap_bytes)
    assert not p_df.empty
    assert len(p_df) >= 8

    susp_df = detect_suspicious_flows(p_df)
    assert not susp_df.empty
    assert any(row["port"] == 4444 for _, row in susp_df.iterrows())
    print(f"      [PASS] PCAP parsed: {len(p_df)} packets dissected, {len(susp_df)} threat flows flagged (Port 4444).")
    return p_df, susp_df


def test_timeline_engine(b_df, d_df, p_df, eml_path: str):
    print("[7/8] Testing timeline_engine.py...")
    with open(eml_path, "rb") as f:
        _, e_df = parse_email(f.read())

    tl_df = build_master_timeline(
        browser_df=b_df,
        downloads_df=d_df,
        pcap_df=p_df,
        email_df=e_df,
    )
    assert not tl_df.empty
    assert "mitre_tactic" in tl_df.columns
    assert any("Initial Access" in str(t) for t in tl_df["mitre_tactic"])
    assert any("Command & Control" in str(t) for t in tl_df["mitre_tactic"])
    print(f"      [PASS] Master Timeline: {len(tl_df)} events correlated with MITRE ATT&CK tags.")
    return tl_df


def test_report_generator(tl_df, paths: dict):
    print("[8/8] Testing report_generator.py...")
    coc_list = []
    for k, p in paths.items():
        with open(p, "rb") as f:
            h = compute_file_hashes(f.read(), os.path.basename(p))
            coc_list.append(h)

    meta = {
        "case_id": "TEST-DFIR-001",
        "case_name": "Automated Test Case",
        "investigator": "Test Lead",
        "agency": "Unit Testing Division",
        "c2_ip": "198.51.100.23",
        "vector": "Phishing",
    }
    eval_res = {
        "total_score": 100,
        "grade": "A (Exemplary)",
        "feedback_summary": "All deductions verified.",
        "breakdown": [
            {"category": "Threat IP", "expected": "198.51.100.23", "submitted": "198.51.100.23", "points": 25, "max_points": 25},
            {"category": "Attack Vector", "expected": "Phishing", "submitted": "Phishing", "points": 25, "max_points": 25},
        ],
    }

    pdf_bytes = generate_forensic_pdf(
        case_metadata=meta,
        chain_of_custody=coc_list,
        timeline_df=tl_df,
        investigator_notes="Automated self-test verification notes.",
        evaluation_results=eval_res,
    )
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000
    print(f"      [PASS] Courtroom PDF Report compiled ({len(pdf_bytes)} bytes) with ISO 27037 ledger.")


if __name__ == "__main__":
    print("=" * 60)
    print(" CYBERTRACE FORENSIC WORKBENCH: AUTOMATED SELF-TEST SUITE")
    print("=" * 60)
    test_evidence_hasher()
    paths = test_mock_evidence_generation()
    test_email_parser(paths["email"])
    test_magic_checker(paths["spoofed_pdf"])
    b_df, d_df = test_browser_parser(paths["history"])
    p_df, susp_df = test_pcap_parser(paths["pcap"])
    tl_df = test_timeline_engine(b_df, d_df, p_df, paths["email"])
    test_report_generator(tl_df, paths)
    print("=" * 60)
    print(" [PASS] ALL 8 FORENSIC ENGINE SELF-TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)
