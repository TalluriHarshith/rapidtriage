"""
RapidTriage Timeline API Router
Retrieves unified, standardized chronological events.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List

from rapidtriage.backend.database.db import get_db
from rapidtriage.backend.database.models import Event, Case

router = APIRouter(prefix="/timeline", tags=["Timeline"])

@router.get("")
def get_timeline(
    case_id: Optional[str] = None,
    artifact: Optional[str] = None,
    risk_status: Optional[str] = None,
    correlation_id: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Returns unified chronological events with optional filters.
    """
    query = db.query(Event)

    if case_id:
        query = query.filter(Event.case_id == case_id)
    else:
        # Use latest case
        latest_case = db.query(Case).order_by(Case.created_at.desc()).first()
        if latest_case:
            query = query.filter(Event.case_id == latest_case.id)

    if artifact and artifact != "all":
        query = query.filter(Event.artifact == artifact)

    if risk_status and risk_status != "all":
        query = query.filter(Event.risk_status == risk_status)

    if correlation_id:
        query = query.filter(Event.correlation_id == correlation_id)

    events = query.all()

    # In-memory search filter for process, path, description, etc.
    if search and search.strip():
        term = search.strip().lower()
        events = [
            e for e in events
            if term in str(e.process).lower()
            or term in str(e.path).lower()
            or term in str(e.description).lower()
            or term in str(e.event_type).lower()
            or term in str(e.user).lower()
        ]

    return [
        {
            "id": e.id,
            "caseId": e.case_id,
            "timestamp": e.timestamp,
            "raw_timestamp": e.raw_timestamp,
            "artifact": e.artifact,
            "event_type": e.event_type,
            "process": e.process or "",
            "process_id": e.process_id or "",
            "path": e.path or "",
            "user": e.user or "SYSTEM",
            "description": e.description,
            "details": e.details or {},
            "risk_status": e.risk_status,
            "risk_score": e.risk_score,
            "risk_reasons": e.risk_reasons or [],
            "correlation_id": e.correlation_id
        }
        for e in events
    ]

@router.get("/{event_id}")
def get_event_detail(event_id: str, db: Session = Depends(get_db)):
    """Returns single event details."""
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    return {
        "id": event.id,
        "caseId": event.case_id,
        "timestamp": event.timestamp,
        "raw_timestamp": event.raw_timestamp,
        "artifact": event.artifact,
        "event_type": event.event_type,
        "process": event.process,
        "process_id": event.process_id,
        "path": event.path,
        "user": event.user,
        "description": event.description,
        "details": event.details,
        "risk_status": event.risk_status,
        "risk_score": event.risk_score,
        "risk_reasons": event.risk_reasons,
        "correlation_id": event.correlation_id
    }
