"""
Magic Byte Checker & File Signature Analyzer (Week 4-5 Syllabus Alignment)
Reads the initial 16 bytes of ingested artifacts, detects the true binary file signature,
and identifies file extension masquerading/spoofing (MITRE ATT&CK T1036: Masquerading).
"""

from typing import Dict, Any, List, Optional
import os


# Magic signature database
SIGNATURE_DATABASE = [
    {
        "name": "Windows PE Executable / DLL / SCR",
        "category": "Executable",
        "magic_bytes": b"\x4D\x5A",
        "hex_pattern": "4D 5A",
        "offset": 0,
        "valid_extensions": [".exe", ".dll", ".sys", ".scr", ".com", ".efi"],
        "mime": "application/x-dosexec",
        "is_executable": True,
    },
    {
        "name": "Portable Document Format (PDF)",
        "category": "Document",
        "magic_bytes": b"\x25\x50\x44\x46",
        "hex_pattern": "25 50 44 46",
        "offset": 0,
        "valid_extensions": [".pdf"],
        "mime": "application/pdf",
        "is_executable": False,
    },
    {
        "name": "Portable Network Graphics (PNG)",
        "category": "Image",
        "magic_bytes": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
        "hex_pattern": "89 50 4E 47 0D 0A 1A 0A",
        "offset": 0,
        "valid_extensions": [".png"],
        "mime": "image/png",
        "is_executable": False,
    },
    {
        "name": "JPEG Image",
        "category": "Image",
        "magic_bytes": b"\xFF\xD8\xFF",
        "hex_pattern": "FF D8 FF",
        "offset": 0,
        "valid_extensions": [".jpg", ".jpeg"],
        "mime": "image/jpeg",
        "is_executable": False,
    },
    {
        "name": "ZIP Archive / OpenXML Office Document",
        "category": "Archive / Office",
        "magic_bytes": b"\x50\x4B\x03\x04",
        "hex_pattern": "50 4B 03 04",
        "offset": 0,
        "valid_extensions": [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"],
        "mime": "application/zip",
        "is_executable": False,
    },
    {
        "name": "SQLite 3 Database",
        "category": "Database",
        "magic_bytes": b"SQLite format 3\x00",
        "hex_pattern": "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00",
        "offset": 0,
        "valid_extensions": [".sqlite", ".sqlite3", ".db", ".db3", ""],
        "mime": "application/vnd.sqlite3",
        "is_executable": False,
    },
    {
        "name": "Linux ELF Executable",
        "category": "Executable",
        "magic_bytes": b"\x7F\x45\x4C\x46",
        "hex_pattern": "7F 45 4C 46",
        "offset": 0,
        "valid_extensions": ["", ".elf", ".bin", ".so"],
        "mime": "application/x-executable",
        "is_executable": True,
    },
    {
        "name": "PCAP Network Capture (Standard Microsecond)",
        "category": "Network Capture",
        "magic_bytes": b"\xD4\xC3\xB2\xA1",
        "hex_pattern": "D4 C3 B2 A1",
        "offset": 0,
        "valid_extensions": [".pcap"],
        "mime": "application/vnd.tcpdump.pcap",
        "is_executable": False,
    },
    {
        "name": "PCAP Network Capture (Big-Endian)",
        "category": "Network Capture",
        "magic_bytes": b"\xA1\xB2\xC3\xD4",
        "hex_pattern": "A1 B2 C3 D4",
        "offset": 0,
        "valid_extensions": [".pcap"],
        "mime": "application/vnd.tcpdump.pcap",
        "is_executable": False,
    },
    {
        "name": "PCAPNG Network Capture",
        "category": "Network Capture",
        "magic_bytes": b"\x0A\x0D\x0D\x0A",
        "hex_pattern": "0A 0D 0D 0A",
        "offset": 0,
        "valid_extensions": [".pcapng", ".pcap"],
        "mime": "application/x-pcapng",
        "is_executable": False,
    },
]


def format_hex_dump(raw_bytes: bytes, length: int = 16) -> str:
    """Formats first N bytes into spaced uppercase hexadecimal string."""
    slice_bytes = raw_bytes[:length]
    return " ".join(f"{b:02X}" for b in slice_bytes)


def format_ascii_dump(raw_bytes: bytes, length: int = 16) -> str:
    """Formats first N bytes into printable ASCII string, replacing non-printables with '.'."""
    slice_bytes = raw_bytes[:length]
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in slice_bytes)


def detect_file_signature(file_bytes: bytes) -> Dict[str, Any]:
    """
    Reads the initial bytes of a binary file and identifies its true file type
    based on magic numbers.
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("file_bytes must be bytes or bytearray")

    raw = bytes(file_bytes)
    hex_dump_16 = format_hex_dump(raw, 16)
    ascii_dump_16 = format_ascii_dump(raw, 16)

    for entry in SIGNATURE_DATABASE:
        magic = entry["magic_bytes"]
        offset = entry["offset"]
        if len(raw) >= offset + len(magic):
            if raw[offset:offset + len(magic)] == magic:
                return {
                    "matched": True,
                    "signature_name": entry["name"],
                    "category": entry["category"],
                    "mime": entry["mime"],
                    "valid_extensions": entry["valid_extensions"],
                    "is_executable": entry["is_executable"],
                    "hex_dump_16": hex_dump_16,
                    "ascii_dump_16": ascii_dump_16,
                    "expected_magic_hex": entry["hex_pattern"],
                }

    return {
        "matched": False,
        "signature_name": "Unknown / Unclassified Binary",
        "category": "Binary Data",
        "mime": "application/octet-stream",
        "valid_extensions": [],
        "is_executable": False,
        "hex_dump_16": hex_dump_16,
        "ascii_dump_16": ascii_dump_16,
        "expected_magic_hex": "N/A",
    }


def check_file_spoofing(filename: str, file_bytes: bytes) -> Dict[str, Any]:
    """
    Compares the declared file extension with the verified magic byte signature.
    Identifies high-risk defense evasion attempts such as executable binaries
    disguised with document extensions (.pdf, .docx, .png).
    """
    sig_info = detect_file_signature(file_bytes)
    _, ext = os.path.splitext(filename.lower())

    is_spoofed = False
    severity = "Low"
    anomaly_reason = "File extension corresponds with binary magic signature."
    mitre_tactic = "None"
    mitre_technique = "None"

    if sig_info["matched"]:
        valid_exts = [e.lower() for e in sig_info["valid_extensions"]]
        # If the file has an extension not in valid_extensions
        if ext and ext not in valid_exts and len(valid_exts) > 0 and valid_exts != [""]:
            is_spoofed = True
            mitre_tactic = "Defense Evasion"
            mitre_technique = "T1036 (Masquerading)"

            if sig_info["is_executable"]:
                severity = "CRITICAL"
                anomaly_reason = (
                    f"CRITICAL DEFENSE EVASION DETECTED: File '{filename}' is disguised as '{ext}', "
                    f"but its magic signature matches {sig_info['signature_name']} (Magic: {sig_info['expected_magic_hex']}). "
                    f"Possible malware delivery via deceptive extension."
                )
            else:
                severity = "Medium"
                anomaly_reason = (
                    f"Extension mismatch: File '{filename}' has extension '{ext}', "
                    f"but file header identifies it as {sig_info['signature_name']}."
                )

    return {
        "filename": filename,
        "declared_extension": ext or "(none)",
        "detected_signature": sig_info["signature_name"],
        "category": sig_info["category"],
        "mime": sig_info["mime"],
        "is_executable": sig_info["is_executable"],
        "is_spoofed": is_spoofed,
        "severity": severity,
        "anomaly_reason": anomaly_reason,
        "hex_dump_16": sig_info["hex_dump_16"],
        "ascii_dump_16": sig_info["ascii_dump_16"],
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
    }
