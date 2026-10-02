"""
RapidTriage Findings API Router
Serves correlated suspicious sequences and risk analysis breakdown.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Optional

from rapidtriage.backend.database.db import get_db
from rapidtriage.backend.database.models import Finding, RiskIndicator, Case

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("")
def get_findings(case_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Returns findings and risk score breakdown for the active investigation."""
    target_case_id = case_id
    if not target_case_id:
        latest = db.query(Case).order_by(Case.created_at.desc()).first()
        if latest:
            target_case_id = latest.id

    if not target_case_id:
        return {"findings": [], "riskSummary": {"score": 0, "level": "Low", "indicators": []}}

    case = db.query(Case).filter(Case.id == target_case_id).first()
    findings = db.query(Finding).filter(Finding.case_id == target_case_id).all()
    indicators = db.query(RiskIndicator).filter(RiskIndicator.case_id == target_case_id).all()

    return {
        "findings": [
            {
                "id": f.id,
                "correlationId": f.correlation_id,
                "title": f.title,
                "description": f.description,
                "riskScore": f.risk_score,
                "priority": f.priority,
                "startTime": f.start_time,
                "endTime": f.end_time,
                "timeSpan": f.time_span,
                "reasons": f.reasons or [],
                "eventIds": f.event_ids or []
            }
            for f in findings
        ],
        "riskSummary": {
            "score": case.risk_score if case else 0,
            "level": case.risk_level if case else "Low",
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
    }
