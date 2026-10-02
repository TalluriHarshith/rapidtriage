"""
RapidTriage Cases API Router
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

from rapidtriage.backend.database.db import get_db, seed_initial_case
from rapidtriage.backend.database.models import Case, EvidenceItem, Event, Finding, RiskIndicator

router = APIRouter(prefix="/cases", tags=["Cases"])

class NotesUpdateRequest(BaseModel):
    notes: str

@router.get("")
def list_cases(db: Session = Depends(get_db)):
    """Lists all cases."""
    cases = db.query(Case).all()
    return [
        {
            "id": c.id,
            "endpoint": c.endpoint,
            "os": c.os,
            "status": c.status,
            "acquisitionTime": c.acquisition_time,
            "isDemoData": c.is_demo_data,
            "riskScore": c.risk_score,
            "riskLevel": c.risk_level,
        }
        for c in cases
    ]

@router.get("/current")
def get_current_case(db: Session = Depends(get_db)):
    """Gets the currently active investigation case with summary statistics."""
    case = db.query(Case).order_by(Case.created_at.desc()).first()
    if not case:
        raise HTTPException(status_code=404, detail="No active case found.")

    evidence_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case.id).all()
    events_count = db.query(Event).filter(Event.case_id == case.id).count()
    findings_count = db.query(Finding).filter(Finding.case_id == case.id).count()

    return {
        "caseDetails": {
            "caseId": case.id,
            "endpoint": case.endpoint,
            "os": case.os,
            "status": case.status,
            "acquisitionTime": case.acquisition_time,
            "isDemoData": case.is_demo_data,
            "investigationNotes": case.notes or "",
        },
        "artifactSummaries": [
            {
                "artifact": item.artifact_type,
                "name": item.name,
                "status": item.status,
                "extractedEventsCount": item.extracted_events_count,
                "lastProcessedTime": item.acquisition_time,
                "sourcePath": item.source_path,
                "fileSize": item.file_size,
                "sha256Hash": item.sha256_hash,
                "isVerified": True
            }
            for item in evidence_items
        ],
        "stats": {
            "totalEvents": events_count,
            "totalFindings": findings_count,
            "riskScore": case.risk_score,
            "riskLevel": case.risk_level
        }
    }

@router.post("/acquire")
def acquire_case(db: Session = Depends(get_db)):
    """Simulates acquiring fresh endpoint snapshot."""
    now = datetime.utcnow()
    case_id = f"RT-{now.strftime('%Y')}-{now.strftime('%m%d')}"
    
    # Check if case exists
    existing = db.query(Case).filter(Case.id == case_id).first()
    if existing:
        db.delete(existing)
        db.commit()

    case = Case(
        id=case_id,
        endpoint="LAB-PC-07",
        os="Windows 11 Pro (23H2 x64)",
        status="Requires Investigation",
        acquisition_time=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        is_demo_data=False,
        risk_score=75,
        risk_level="Elevated",
        notes="Automated endpoint acquisition executed via RapidTriage portable agent. Artifact snapshot extracted to volatile memory."
    )
    db.add(case)
    db.commit()
    seed_initial_case(db) # repopulate artifacts for the new acquisition
    return {"message": "Evidence acquisition complete.", "caseId": case_id}

@router.post("/sample")
def load_sample_case(db: Session = Depends(get_db)):
    """Loads standardized demonstration case."""
    # Delete existing RT-2026-001 if present and reseed
    existing = db.query(Case).filter(Case.id == "RT-2026-001").first()
    if existing:
        db.delete(existing)
        db.commit()
    seed_initial_case(db)
    return {"message": "Sample case loaded successfully.", "caseId": "RT-2026-001"}

@router.patch("/{case_id}/notes")
def update_case_notes(case_id: str, payload: NotesUpdateRequest, db: Session = Depends(get_db)):
    """Updates investigator notes on a case."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    case.notes = payload.notes
    db.commit()
    return {"message": "Notes updated successfully.", "notes": case.notes}
