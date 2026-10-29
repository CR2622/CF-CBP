"""
Evidence Hasher & Chain of Custody Logger (ISO/IEC 27037 Compliance)
Provides non-destructive in-memory cryptographic hashing, evidence metadata tracking,
and baseline integrity verification for courtroom digital evidence validation.
"""

import hashlib
from datetime import datetime, timezone


def format_bytes_human(num_bytes: int) -> str:
    """Formats raw byte count into human-readable string (KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def compute_file_hashes(file_bytes: bytes, filename: str, custodian: str = "Lead Forensic Examiner") -> dict:
    """
    Computes cryptographic hashes (MD5 and SHA-256) of raw in-memory evidence bytes,
    records file byte size, and captures the acquisition timestamp in UTC.

    ISO/IEC 27037 Standard:
    Digital evidence must be documented with an unambiguous hash baseline prior to
    analysis to guarantee non-repudiation and evidence integrity throughout the investigation.

    Args:
        file_bytes: Raw bytes of the uploaded/ingested artifact.
        filename: Name of the evidence item.
        custodian: Investigator or forensic lab personnel receiving the evidence.

    Returns:
        dict containing evidence custody metadata, cryptographic digests, and timestamps.
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError(f"Expected file_bytes to be bytes, got {type(file_bytes).__name__}")

    raw_bytes = bytes(file_bytes)
    md5_hash = hashlib.md5(raw_bytes).hexdigest().lower()
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest().lower()
    byte_count = len(raw_bytes)
    acquisition_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return {
        "filename": filename,
        "file_size_bytes": byte_count,
        "file_size_human": format_bytes_human(byte_count),
        "md5": md5_hash,
        "sha256": sha256_hash,
        "acquisition_time": acquisition_time,
        "custodian": custodian,
        "verification_status": "VERIFIED (Baseline Established)",
        "tamper_detected": False,
    }


def verify_integrity(original_hash: str, current_bytes: bytes) -> bool:
    """
    Recalculates the cryptographic hash of the current bytes and compares it against
    the baseline hash recorded during acquisition.

    Args:
        original_hash: The recorded MD5 or SHA-256 baseline string.
        current_bytes: The byte stream of the artifact to verify.

    Returns:
        True if the recalculated hash matches the baseline (evidence intact).
        False if there is a mismatch (evidence tampering or corruption detected).
    """
    if not original_hash or not isinstance(current_bytes, (bytes, bytearray)):
        return False

    cleaned_orig = original_hash.strip().lower()
    raw = bytes(current_bytes)

    if len(cleaned_orig) == 64:
        current_hash = hashlib.sha256(raw).hexdigest().lower()
        return current_hash == cleaned_orig
    elif len(cleaned_orig) == 32:
        current_hash = hashlib.md5(raw).hexdigest().lower()
        return current_hash == cleaned_orig
    else:
        # Fallback check both
        sha256_val = hashlib.sha256(raw).hexdigest().lower()
        md5_val = hashlib.md5(raw).hexdigest().lower()
        return cleaned_orig in (sha256_val, md5_val)
