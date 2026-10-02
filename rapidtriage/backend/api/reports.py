"""
RapidTriage Reports API Router
Handles ReportLab PDF generation and file downloads.
"""

from fastapi import APIRouter, Depends, HTTPException, Body
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional
from pathlib import Path
import os

from rapidtriage.backend.config import REPORTS_DIR
from rapidtriage.backend.database.db import get_db
from rapidtriage.backend.database.models import Case, EvidenceItem, Event, Finding, RiskIndicator
from rapidtriage.backend.reports.pdf_generator import generate_pdf_report, sanitize_filename

router = APIRouter(tags=["Reports"])

@router.post("/reports/generate")
def generate_report(case_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Generates PDF report for a case in database using ReportLab."""
    target_case_id = case_id
    if not target_case_id:
        latest = db.query(Case).order_by(Case.created_at.desc()).first()
        if not latest:
            raise HTTPException(status_code=404, detail="No case available to generate report.")
        target_case_id = latest.id

    case = db.query(Case).filter(Case.id == target_case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    evidence_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()
    events = db.query(Event).filter(Event.case_id == case.id).order_by(Event.timestamp).all()
    findings = db.query(Finding).filter(Finding.case_id == case.id).all()
    indicators = db.query(RiskIndicator).filter(RiskIndicator.case_id == case.id).all()

    case_details = {
        "caseId": case.id,
        "endpoint": case.endpoint,
        "os": case.os,
        "status": case.status,
        "acquisitionTime": case.acquisition_time,
        "isDemoData": case.is_demo_data
    }

    artifact_summaries = [
        {
            "name": item.name,
            "sourcePath": item.source_path,
            "extractedEventsCount": item.extracted_events_count,
            "sha256Hash": item.sha256_hash,
            "status": item.status
        }
        for item in evidence_items
    ]

    events_data = [
        {
            "id": e.id,
            "timestamp": e.timestamp,
            "artifact": e.artifact,
            "event_type": e.event_type,
            "process": e.process,
            "path": e.path,
            "user": e.user,
            "risk_status": e.risk_status,
            "correlation_id": e.correlation_id
        }
        for e in events
    ]

    findings_data = [
        {
            "title": f.title,
            "riskScore": f.risk_score,
            "priority": f.priority,
            "startTime": f.start_time,
            "endTime": f.end_time,
            "timeSpan": f.time_span,
            "reasons": f.reasons or [],
            "eventIds": f.event_ids or []
        }
        for f in findings
    ]

    case_risk_summary = {
        "score": case.risk_score,
        "level": case.risk_level,
        "indicators": [
            {
                "title": ind.title,
                "points": ind.points,
                "description": ind.description,
                "category": ind.category
            }
            for ind in indicators
        ]
    }

    pdf_path = generate_pdf_report(
        case_details=case_details,
        artifact_summaries=artifact_summaries,
        events=events_data,
        findings=findings_data,
        case_risk_summary=case_risk_summary,
        notes=case.notes or ""
    )

    return {
        "success": True,
        "filename": pdf_path.name,
        "downloadUrl": f"/api/reports/download/{pdf_path.name}",
        "fileSizeBytes": pdf_path.stat().st_size
    }

@router.get("/reports/download/{filename}")
def download_report(filename: str):
    """Downloads generated PDF report file."""
    safe_name = sanitize_filename(filename)
    file_path = REPORTS_DIR / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Requested PDF report file was not found.")

    return FileResponse(
        path=str(file_path),
        media_type="application/pdf",
        filename=safe_name,
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
    )

@router.post("/generate-pdf")
def direct_generate_pdf(payload: Dict[str, Any] = Body(...)):
    """
    Direct PDF generation from frontend JSON payload.
    Returns binary application/pdf response for immediate browser download.
    """
    case_details = payload.get("caseDetails", {})
    artifact_summaries = payload.get("artifactSummaries", [])
    events = payload.get("events", [])
    findings = payload.get("findings", [])
    case_risk_summary = payload.get("caseRiskSummary", {})
    notes = payload.get("notes", "")

    pdf_path = generate_pdf_report(
        case_details=case_details,
        artifact_summaries=artifact_summaries,
        events=events,
        findings=findings,
        case_risk_summary=case_risk_summary,
        notes=notes
    )

    if not pdf_path.exists() or pdf_path.stat().st_size < 500:
        raise HTTPException(status_code=500, detail="Failed to produce valid PDF report.")

    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{pdf_path.name}"',
            "Content-Length": str(len(pdf_bytes))
        }
    )
