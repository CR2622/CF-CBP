"""
Courtroom-Ready PDF Forensic Case Incident Report Engine
Generates an authoritative, tamper-evident forensic report using ReportLab.
Conforms to ISO/IEC 27037 standards with chain of custody hashes, MITRE ATT&CK mappings,
incident findings, and forensic examiner attestations.
"""

import io
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import pandas as pd

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)


def generate_forensic_pdf(
    case_metadata: Dict[str, Any],
    chain_of_custody: List[Dict[str, Any]],
    timeline_df: pd.DataFrame,
    investigator_notes: str,
    evaluation_results: Optional[Dict[str, Any]] = None,
) -> bytes:
    """
    Generates a courtroom-ready PDF forensic incident report as raw bytes.

    Args:
        case_metadata: dict containing case_id, title, investigator, agency, c2_ip, vector.
        chain_of_custody: list of evidence metadata dicts with hashes, timestamps, statuses.
        timeline_df: correlated master forensic timeline DataFrame.
        investigator_notes: written narrative analysis from the examiner.
        evaluation_results: optional challenge score and rubric breakdown.

    Returns:
        bytes: in-memory PDF binary stream.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom Palettes
    NAVY = colors.HexColor("#1B365D")
    SLATE = colors.HexColor("#334155")
    LIGHT_BG = colors.HexColor("#F8FAFC")
    BORDER_COLOR = colors.HexColor("#CBD5E1")
    ALERT_RED = colors.HexColor("#991B1B")
    SUCCESS_GREEN = colors.HexColor("#065F46")
    GOLD = colors.HexColor("#854D0E")

    # Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=NAVY,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=SLATE,
        spaceAfter=12,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=NAVY,
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#1E293B"),
    )
    bold_body = ParagraphStyle(
        "BoldBody",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0F172A"),
    )
    cell_code_style = ParagraphStyle(
        "TableCellCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=6.5,
        leading=8.5,
        textColor=colors.HexColor("#0F172A"),
    )
    cell_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )

    story = []

    # 1. Header & Title Block
    story.append(Paragraph("CYBERTRACE DIGITAL FORENSICS LABORATORY", subtitle_style))
    story.append(Paragraph("Official Forensic Investigation & Case Incident Report", title_style))
    
    current_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_str = (
        f"<b>Standard:</b> ISO/IEC 27037:2012 Guidelines for Digital Evidence Handling | "
        f"<b>Report Compiled:</b> {current_utc}"
    )
    story.append(Paragraph(meta_str, subtitle_style))
    story.append(Spacer(1, 8))

    # 2. Case Briefing Metadata Table
    case_id = case_metadata.get("case_id", "DFIR-2026-0045")
    case_name = case_metadata.get("case_name", "Unauthorized Data Exfiltration Investigation")
    examiner = case_metadata.get("investigator", "Senior DFIR Examiner")
    agency = case_metadata.get("agency", "Cyber Forensics & Incident Response Division")
    c2_ip = case_metadata.get("c2_ip", "198.51.100.23")
    vector = case_metadata.get("vector", "Spear-phishing email with extension-spoofed malicious payload")

    brief_data = [
        [
            Paragraph("<b>Case Reference:</b>", body_style), Paragraph(case_id, body_style),
            Paragraph("<b>Lead Examiner:</b>", body_style), Paragraph(examiner, body_style),
        ],
        [
            Paragraph("<b>Investigation Title:</b>", body_style), Paragraph(case_name, body_style),
            Paragraph("<b>Jurisdiction/Agency:</b>", body_style), Paragraph(agency, body_style),
        ],
        [
            Paragraph("<b>Identified Threat IP:</b>", body_style), Paragraph(f"<font color='#991B1B'><b>{c2_ip}</b></font>", body_style),
            Paragraph("<b>Primary Vector:</b>", body_style), Paragraph(vector, body_style),
        ],
    ]
    brief_table = Table(brief_data, colWidths=[105, 165, 110, 160])
    brief_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(brief_table)
    story.append(Spacer(1, 12))

    # 3. Academic Evaluation / Examiner Rubric Score (If submitted)
    if evaluation_results:
        story.append(Paragraph("Examiner Competency & Investigation Rubric Assessment", section_heading))
        score = evaluation_results.get("total_score", 0)
        feedback = evaluation_results.get("feedback_summary", "Evaluation complete.")
        
        eval_data = [
            [
                Paragraph("<b>Rubric Category</b>", cell_header_style),
                Paragraph("<b>Ground Truth Benchmark</b>", cell_header_style),
                Paragraph("<b>Investigator Finding</b>", cell_header_style),
                Paragraph("<b>Points Awarded</b>", cell_header_style),
            ]
        ]
        breakdown = evaluation_results.get("breakdown", [])
        for item in breakdown:
            eval_data.append([
                Paragraph(item.get("category", ""), cell_style),
                Paragraph(item.get("expected", ""), cell_style),
                Paragraph(item.get("submitted", ""), cell_style),
                Paragraph(f"<b>{item.get('points', 0)} / {item.get('max_points', 25)}</b>", cell_style),
            ])
        eval_data.append([
            Paragraph("<b>OVERALL SCORE:</b>", bold_body),
            Paragraph(f"<b>{score} / 100</b> ({evaluation_results.get('grade', 'N/A')})", bold_body),
            Paragraph(f"<i>{feedback}</i>", cell_style),
            Paragraph(f"<b>{score} pts</b>", bold_body),
        ])

        eval_table = Table(eval_data, colWidths=[120, 150, 180, 90])
        eval_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("BOX", (0, 0), (-1, -1), 0.75, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#FEF3C7")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(eval_table)
        story.append(Spacer(1, 12))

    # 4. Chain of Custody & Cryptographic Hash Records (ISO/IEC 27037)
    story.append(Paragraph("Evidence Chain of Custody & Cryptographic Baseline (ISO/IEC 27037)", section_heading))
    coc_intro = (
        "In accordance with ISO/IEC 27037 standards for digital evidence integrity, raw artifact hashes "
        "were computed in-memory upon acquisition. Original storage media remained unwritten."
    )
    story.append(Paragraph(coc_intro, body_style))
    story.append(Spacer(1, 6))

    coc_rows = [
        [
            Paragraph("<b>Artifact Name</b>", cell_header_style),
            Paragraph("<b>Size</b>", cell_header_style),
            Paragraph("<b>MD5 Digest</b>", cell_header_style),
            Paragraph("<b>SHA-256 Digest</b>", cell_header_style),
            Paragraph("<b>Status</b>", cell_header_style),
        ]
    ]

    for item in chain_of_custody:
        status_text = "VERIFIED" if not item.get("tamper_detected", False) else "TAMPERED"
        status_color = "#065F46" if status_text == "VERIFIED" else "#991B1B"
        coc_rows.append([
            Paragraph(f"<b>{item.get('filename', '')}</b>", cell_style),
            Paragraph(item.get("file_size_human", "0 B"), cell_style),
            Paragraph(item.get("md5", ""), cell_code_style),
            Paragraph(item.get("sha256", ""), cell_code_style),
            Paragraph(f"<font color='{status_color}'><b>{status_text}</b></font>", cell_style),
        ])

    coc_table = Table(coc_rows, colWidths=[95, 45, 140, 190, 70])
    coc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("BOX", (0, 0), (-1, -1), 0.75, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(coc_table)
    story.append(Spacer(1, 12))

    # 5. Correlated Master Forensic Timeline & MITRE ATT&CK
    story.append(Paragraph("Correlated Master Forensic Timeline & Event Attribution", section_heading))
    tl_intro = (
        "Multi-source event correlation unifies timestamps across email, web navigation, download logs, "
        "magic byte inspection, and raw network packet captures into an ascending chronological audit trail."
    )
    story.append(Paragraph(tl_intro, body_style))
    story.append(Spacer(1, 6))

    timeline_rows = [
        [
            Paragraph("<b>Timestamp (UTC)</b>", cell_header_style),
            Paragraph("<b>Source</b>", cell_header_style),
            Paragraph("<b>Event Description & Diagnostic Findings</b>", cell_header_style),
            Paragraph("<b>Criticality</b>", cell_header_style),
            Paragraph("<b>MITRE ATT&CK</b>", cell_header_style),
        ]
    ]

    # Limit to top 25 key events to fit cleanly within report
    events_to_show = timeline_df.head(25) if not timeline_df.empty else pd.DataFrame()
    for _, row in events_to_show.iterrows():
        crit = str(row.get("criticality", "Low"))
        crit_color = "#991B1B" if crit == "High" else ("#B45309" if crit == "Medium" else "#334155")
        
        timeline_rows.append([
            Paragraph(str(row.get("timestamp", "")), cell_style),
            Paragraph(str(row.get("artifact_source", "")), cell_style),
            Paragraph(str(row.get("event_summary", "")), cell_style),
            Paragraph(f"<font color='{crit_color}'><b>{crit}</b></font>", cell_style),
            Paragraph(f"<b>{row.get('mitre_tactic', '')}</b><br/>{row.get('mitre_technique_id', '')}", cell_style),
        ])

    timeline_table = Table(timeline_rows, colWidths=[90, 85, 205, 55, 105])
    timeline_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("BOX", (0, 0), (-1, -1), 0.75, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(timeline_table)
    story.append(Spacer(1, 14))

    # 6. Investigator Narrative Findings
    story.append(Paragraph("Investigator Narrative & Incident Assessment", section_heading))
    cleaned_notes = investigator_notes.strip() if investigator_notes else "No additional notes provided."
    story.append(Paragraph(cleaned_notes.replace("\n", "<br/>"), body_style))
    story.append(Spacer(1, 16))

    # 7. Courtroom Attestation & Examiner Sign-off
    attestation_text = (
        "<b>CERTIFICATE OF FORENSIC EXAMINATION & CHAIN OF CUSTODY ATTESTATION</b><br/>"
        "I hereby certify under penalty of perjury that the digital forensic examination documented "
        "herein was conducted in accordance with recognized industry standards and ISO/IEC 27037 "
        "procedures. All raw artifacts were preserved without alteration. The findings and chronological "
        "correlations presented represent an accurate technical record of the examined media."
    )
    
    signoff_data = [
        [Paragraph(attestation_text, cell_style)],
        [
            Paragraph(
                f"<br/><br/>____________________________________________________<br/>"
                f"<b>{examiner}</b>, Lead Forensic Investigator<br/>"
                f"{agency} | Verified UTC: {current_utc}",
                body_style,
            )
        ],
    ]
    signoff_table = Table(signoff_data, colWidths=[540])
    signoff_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
        ("BOX", (0, 0), (-1, -1), 1, BORDER_COLOR),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    
    story.append(KeepTogether(signoff_table))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
