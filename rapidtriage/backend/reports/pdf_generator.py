"""
RapidTriage ReportLab PDF Generator
Generates a complete, professional digital forensic case report matching the RapidTriage design language.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from rapidtriage.backend.config import REPORTS_DIR

def sanitize_filename(name: str) -> str:
    """Sanitizes case ID for filename safety."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)

def generate_pdf_report(
    case_details: Dict[str, Any],
    artifact_summaries: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    case_risk_summary: Dict[str, Any],
    notes: str = ""
) -> Path:
    """
    Generates a comprehensive PDF forensic report using ReportLab.
    Returns: Path to generated PDF file
    """
    case_id = case_details.get("caseId") or case_details.get("id") or "RT-2026-001"
    endpoint = case_details.get("endpoint") or "LAB-PC-07"
    os_name = case_details.get("os") or "Windows 11 Pro"
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    safe_case = sanitize_filename(case_id)
    
    filename = f"RapidTriage_Case_{safe_case}_{date_str}.pdf"
    output_path = REPORTS_DIR / filename

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a')
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#eab308')
    )
    meta_style = ParagraphStyle(
        'DocMeta',
        parent=styles['Normal'],
        fontName='Courier-Bold',
        fontSize=8,
        leading=10,
        alignment=2, # Right align
        textColor=colors.HexColor('#0f172a')
    )
    h1_style = ParagraphStyle(
        'Heading1Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4,
        spaceBefore=10
    )
    body_style = ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor('#334155')
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#1e293b')
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#0f172a')
    )
    table_cell_mono = ParagraphStyle(
        'TableCellMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=6.5,
        leading=8,
        textColor=colors.HexColor('#475569')
    )

    story = []

    # 1. Yellow Evidence Bar Accent
    story.append(HRFlowable(width="100%", thickness=4, color=colors.HexColor("#eab308"), spaceAfter=8, spaceBefore=0))

    # Header row: Title on left, Case ID on right
    header_data = [
        [
            Paragraph("<b>RapidTriage</b>", title_style),
            Paragraph(f"<b>CASE: {case_id}</b><br/><font color='#64748b'>HOST: {endpoint}</font><br/><font color='#64748b'>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</font>", meta_style)
        ],
        [
            Paragraph("PORTABLE ENDPOINT FORENSIC TRIAGE & INCIDENT TIMELINE REPORT", subtitle_style),
            Paragraph("", meta_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[340, 180])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ('TOPPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10, spaceBefore=6))

    # 2. Executive Summary
    story.append(Paragraph("1. EXECUTIVE SUMMARY", h1_style))
    summary_text = (
        f"RapidTriage parsed and standardized {len(events)} endpoint events across browser SQLite databases, "
        f"Windows registry hives, prefetch execution traces, and active network connections for endpoint "
        f"<b>{endpoint}</b> ({os_name}). Correlation analysis identified {len(findings)} sequence(s) requiring manual "
        f"investigator triage. Non-destructive read-only triage was maintained throughout analysis."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 8))

    # 3. Case Information
    story.append(Paragraph("2. CASE INFORMATION", h1_style))
    case_info_data = [
        [Paragraph("Case ID", table_cell_bold), Paragraph(case_id, table_cell_mono), Paragraph("Investigation Status", table_cell_bold), Paragraph(case_details.get("status", "Requires Investigation"), table_cell)],
        [Paragraph("Endpoint Host", table_cell_bold), Paragraph(endpoint, table_cell), Paragraph("Acquisition Time", table_cell_bold), Paragraph(case_details.get("acquisitionTime", "N/A"), table_cell_mono)],
        [Paragraph("Operating System", table_cell_bold), Paragraph(os_name, table_cell), Paragraph("Data Source", table_cell_bold), Paragraph("Demonstration Dataset" if case_details.get("isDemoData") else "Acquired Artifacts", table_cell)],
    ]
    info_table = Table(case_info_data, colWidths=[100, 160, 110, 150])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 8))

    # 4. Evidence Inventory
    story.append(Paragraph("3. EVIDENCE INVENTORY & SHA-256 INTEGRITY", h1_style))
    inv_data = [[
        Paragraph("Artifact Source", table_cell_bold),
        Paragraph("Extracted Path", table_cell_bold),
        Paragraph("Events", table_cell_bold),
        Paragraph("SHA-256 Hash", table_cell_bold)
    ]]
    for art in (artifact_summaries or []):
        inv_data.append([
            Paragraph(f"<b>{art.get('name', 'Artifact')}</b>", table_cell),
            Paragraph(art.get('sourcePath', 'N/A'), table_cell_mono),
            Paragraph(str(art.get('extractedEventsCount', 0)), table_cell),
            Paragraph(f"<font size=5>{art.get('sha256Hash', 'N/A')}</font>", table_cell_mono)
        ])
    inv_table = Table(inv_data, colWidths=[130, 160, 45, 185])
    inv_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(inv_table)
    story.append(Spacer(1, 8))

    # 5. Risk Assessment Summary
    story.append(Paragraph("4. INVESTIGATION RISK SUMMARY", h1_style))
    score = case_risk_summary.get("score", 0)
    level = case_risk_summary.get("level", "Low")
    risk_summary_text = (
        f"<b>Investigation Risk Score: {score}/100</b> ({level}) — "
        f"Calculated via standardized scoring of correlated endpoint behavioral indicators."
    )
    story.append(Paragraph(risk_summary_text, body_style))
    story.append(Spacer(1, 4))

    indicators = case_risk_summary.get("indicators", [])
    if indicators:
        ind_data = [[
            Paragraph("Indicator Title", table_cell_bold),
            Paragraph("Points", table_cell_bold),
            Paragraph("Category", table_cell_bold),
            Paragraph("Forensic Context", table_cell_bold)
        ]]
        for ind in indicators:
            ind_data.append([
                Paragraph(ind.get("title", ""), table_cell_bold),
                Paragraph(f"+{ind.get('points', 0)}", table_cell),
                Paragraph(ind.get("category", "Execution"), table_cell),
                Paragraph(ind.get("description", ""), table_cell)
            ])
        ind_table = Table(ind_data, colWidths=[160, 45, 75, 240])
        ind_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ]))
        story.append(ind_table)

    story.append(Spacer(1, 8))

    # 6. Unified Timeline
    story.append(Paragraph("5. UNIFIED INCIDENT TIMELINE", h1_style))
    tl_data = [[
        Paragraph("Time", table_cell_bold),
        Paragraph("Artifact", table_cell_bold),
        Paragraph("Event Type", table_cell_bold),
        Paragraph("Process / Path", table_cell_bold),
        Paragraph("Risk / Corr", table_cell_bold)
    ]]
    for ev in events[:25]: # First 25 events for report conciseness
        risk_str = ev.get('risk_status', 'normal').upper()
        corr = ev.get('correlation_id') or ''
        badge = f"{risk_str} ({corr})" if corr else risk_str
        tl_data.append([
            Paragraph(ev.get("timestamp", ""), table_cell_mono),
            Paragraph(ev.get("artifact", "").upper(), table_cell),
            Paragraph(ev.get("event_type", ""), table_cell_bold),
            Paragraph(f"{ev.get('process', '')}<br/><font color='#64748b' size=5.5>{ev.get('path', '')[:55]}</font>", table_cell),
            Paragraph(badge, table_cell_mono)
        ])
    tl_table = Table(tl_data, colWidths=[55, 60, 105, 230, 70])
    tl_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
    ]))
    story.append(tl_table)
    story.append(Spacer(1, 8))

    # 7. Findings & Correlated Activity Sequences
    story.append(Paragraph("6. CORRELATED ACTIVITY SEQUENCES (FINDINGS)", h1_style))
    for f in findings:
        f_data = [
            [
                Paragraph(f"<b>{f.get('title')}</b>", table_cell_bold),
                Paragraph(f"<b>SCORE: {f.get('riskScore', 0)}/100</b> ({f.get('priority', 'High')})", meta_style)
            ],
            [
                Paragraph(f"Span: {f.get('timeSpan')} ({f.get('startTime')} → {f.get('endTime')}) | Events: {', '.join(f.get('eventIds', []))}<br/>"
                          f"Reasons: {' | '.join(f.get('reasons', []))}", body_style),
                Paragraph("", body_style)
            ]
        ]
        f_table = Table(f_data, colWidths=[380, 140])
        f_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(f_table)
        story.append(Spacer(1, 4))

    # 8. Integrity & Notes & Conclusion
    story.append(Spacer(1, 4))
    story.append(Paragraph("7. INVESTIGATION NOTES", h1_style))
    notes_text = notes.strip() if notes and notes.strip() else "No additional notes recorded by the investigator."
    story.append(Paragraph(notes_text, body_style))

    story.append(Spacer(1, 4))
    story.append(Paragraph("8. CONCLUSION", h1_style))
    story.append(Paragraph(
        "<i>The identified activity sequences have been highlighted for forensic review based on deterministic "
        "correlation rules. RapidTriage does not definitively categorize findings as malicious.</i>",
        body_style
    ))

    # Build PDF
    doc.build(story)
    return output_path
