"""
CyberTrace Forensic Parsers Package
Provides non-destructive evidence ingestion, cryptographic hashing, 
Chromium artifact extraction, network packet inspection, email forensics,
magic byte validation, and cross-source timeline correlation.
"""

from .evidence_hasher import compute_file_hashes, verify_integrity
from .browser_parser import parse_chromium_history, parse_chromium_downloads
from .email_parser import parse_email
from .magic_checker import detect_file_signature, check_file_spoofing
from .pcap_parser import parse_pcap, detect_suspicious_flows
from .timeline_engine import build_master_timeline

__all__ = [
    "compute_file_hashes",
    "verify_integrity",
    "parse_chromium_history",
    "parse_chromium_downloads",
    "parse_email",
    "detect_file_signature",
    "check_file_spoofing",
    "parse_pcap",
    "detect_suspicious_flows",
    "build_master_timeline",
]
