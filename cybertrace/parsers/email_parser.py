"""
RFC 822 / MIME Email Parser & Phishing Forensics (Week 1 Syllabus Alignment)
Extracts email metadata, traces originating IP hops, inspects SPF/DKIM authentication,
and analyzes embedded hyperlinks for phishing / C2 staging indicators.
"""

import email
from email import policy
from email.utils import parsedate_to_datetime
import re
from datetime import datetime, timezone
from typing import Tuple, Dict, Any, List
import pandas as pd


# Regex patterns for forensic extraction
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_PATTERN = re.compile(r'https?://[^\s<>"\',;]+', re.IGNORECASE)


def extract_originating_ip(received_headers: List[str]) -> Tuple[str, List[str]]:
    """
    Parses 'Received' headers chronologically from earliest hop to latest hop
    to isolate the originating public IP address of the sender.
    """
    all_hops = []
    originating_ip = "Unknown / Local"

    # RFC 5322: Received headers are prepended; the bottom-most header is typically the origin hop
    for header in reversed(received_headers):
        ips = IP_PATTERN.findall(header)
        for ip in ips:
            # Filter out standard RFC 1918 internal IPs for origin if public IP exists
            all_hops.append(ip)
            if not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")):
                originating_ip = ip

    if originating_ip == "Unknown / Local" and all_hops:
        originating_ip = all_hops[0]

    return originating_ip, all_hops


def check_auth_results(msg: email.message.EmailMessage) -> Dict[str, Any]:
    """
    Inspects Authentication-Results, Received-SPF, and DKIM headers
    to determine if sender authentication failed (common in phishing & spoofing).
    """
    auth_header = msg.get("Authentication-Results", "")
    spf_header = msg.get("Received-SPF", "")
    dkim_header = msg.get("DKIM-Signature", "")

    spf_status = "UNKNOWN"
    dkim_status = "UNKNOWN"
    is_spoofed = False

    combined_auth = f"{auth_header} {spf_header}".lower()

    if "spf=fail" in combined_auth or "fail" in spf_header.lower() or "softfail" in combined_auth:
        spf_status = "FAIL (Spoofing Suspected)"
        is_spoofed = True
    elif "spf=pass" in combined_auth or "pass" in spf_header.lower():
        spf_status = "PASS"

    if "dkim=fail" in combined_auth or "bad signature" in combined_auth:
        dkim_status = "FAIL (Signature Invalid)"
        is_spoofed = True
    elif "dkim=pass" in combined_auth:
        dkim_status = "PASS"
    elif not dkim_header and "dkim=none" in combined_auth:
        dkim_status = "NONE (Unsigned)"

    return {
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "is_spoofed": is_spoofed,
        "raw_spf": spf_header.strip() if spf_header else "None",
        "raw_auth": auth_header.strip() if auth_header else "None",
    }


def extract_body_and_links(msg: email.message.EmailMessage) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Extracts plain text / HTML body content and inspects all embedded URLs for threat indicators.
    """
    body_text = ""
    links = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get("Content-Disposition", ""))
            if "attachment" in cdispo:
                continue
            if ctype in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_text += " " + payload.decode(charset, errors="replace")
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                body_text = payload.decode(charset, errors="replace")
            else:
                body_text = str(msg.get_payload() or "")
        except Exception:
            body_text = str(msg.get_payload() or "")

    # Extract all URLs
    raw_urls = URL_PATTERN.findall(body_text)
    # Deduplicate while preserving order
    seen_urls = set()
    for url in raw_urls:
        clean_url = url.rstrip('">)[].,')
        if clean_url in seen_urls:
            continue
        seen_urls.add(clean_url)

        # Threat heuristics
        is_ip_based = bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", clean_url))
        is_executable_link = bool(re.search(r"\.(exe|scr|bat|vbs|ps1|dll|zip)(\?.*)?$", clean_url, re.IGNORECASE))
        has_suspicious_keywords = any(kw in clean_url.lower() for kw in ["secure-update", "verify", "login", "payload", "c2", "invoice", "urgent"])

        threat_level = "Low"
        reasons = []
        if is_ip_based:
            threat_level = "High"
            reasons.append("Raw IP Hostname")
        if is_executable_link:
            threat_level = "High"
            reasons.append("Direct Binary Download")
        if has_suspicious_keywords and threat_level != "High":
            threat_level = "Medium"
            reasons.append("Phishing Domain Keywords")

        links.append({
            "url": clean_url,
            "threat_level": threat_level,
            "reasons": ", ".join(reasons) if reasons else "Standard Link",
        })

    return body_text.strip(), links


def parse_email(file_bytes: bytes) -> Tuple[Dict[str, Any], pd.DataFrame]:
    """
    Ingests raw .eml bytes, non-destructively parses RFC 822 MIME message,
    and returns a structured forensic audit dictionary and a timeline-ready DataFrame.

    Returns:
        (parsed_dict, email_df)
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("file_bytes must be bytes or bytearray")

    msg = email.message_from_bytes(bytes(file_bytes), policy=policy.default)

    # Headers
    sender = str(msg.get("From", "Unknown Sender"))
    recipient = str(msg.get("To", "Unknown Recipient"))
    subject = str(msg.get("Subject", "(No Subject)"))
    date_raw = msg.get("Date", None)

    # Date normalization to UTC
    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if date_raw:
        try:
            dt = parsedate_to_datetime(date_raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            timestamp_utc = dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            pass

    # Received headers and originating IP
    received_headers = msg.get_all("Received", [])
    originating_ip, hop_list = extract_originating_ip(received_headers)

    # SPF / DKIM verification
    auth_info = check_auth_results(msg)

    # Body and Hyperlink extraction
    body_text, links = extract_body_and_links(msg)

    # Overall criticality
    criticality = "Low"
    if auth_info["is_spoofed"] or any(l["threat_level"] == "High" for l in links):
        criticality = "High"
    elif any(l["threat_level"] == "Medium" for l in links):
        criticality = "Medium"

    parsed_dict = {
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "date_utc": timestamp_utc,
        "originating_ip": originating_ip,
        "hop_list": hop_list,
        "auth_info": auth_info,
        "links": links,
        "body_preview": body_text[:500] + ("..." if len(body_text) > 500 else ""),
        "criticality": criticality,
    }

    # Construct DataFrame for Master Timeline correlation
    df_data = [{
        "timestamp": timestamp_utc,
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "originating_ip": originating_ip,
        "spf_status": auth_info["spf_status"],
        "dkim_status": auth_info["dkim_status"],
        "links_count": len(links),
        "criticality": criticality,
        "source": "Email (.eml)",
    }]
    email_df = pd.DataFrame(df_data)

    return parsed_dict, email_df
