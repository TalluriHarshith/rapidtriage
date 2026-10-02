"""
RapidTriage Evidence API Router
Handles manual CSV/JSON upload, preview validation, artifact inventory, and sample CSV downloads.
"""

from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any, List
from datetime import datetime

from rapidtriage.backend.database.db import get_db
from rapidtriage.backend.database.models import Case, EvidenceItem, Event, Finding, RiskIndicator
from rapidtriage.backend.forensic.hasher import compute_sha256
from rapidtriage.backend.parsers.csv_parser import parse_csv_bytes
from rapidtriage.backend.parsers.json_parser import parse_json_bytes
from rapidtriage.backend.analysis.correlator import run_correlation
from rapidtriage.backend.analysis.risk_scorer import calculate_case_risk

router = APIRouter(prefix="/evidence", tags=["Evidence"])

SAMPLE_CSV_CONTENT = """timestamp,event_type,process,path,user,description
10:30:12,Website Visited,chrome.exe,https://dist-software-update.cc/client,Admin,Visited external software distribution portal
10:30:18,File Download,chrome.exe,C:\\Users\\Admin\\Downloads\\update.exe,Admin,Downloaded binary update.exe to user folder
10:32:05,Device Connected,SYSTEM,USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra,SYSTEM,Removable USB storage drive mounted
10:36:02,Process Executed,update.exe,C:\\Users\\Admin\\AppData\\Roaming\\update.exe,Admin,Prefetch indicates binary launch from AppData
10:36:15,Network Connection,update.exe,185.220.101.45:443,Admin,Outbound TCP network session to external IP
10:38:22,Process Executed,cmd.exe,C:\\Windows\\System32\\cmd.exe /c whoami,Admin,Command interpreter executed discovery
10:40:00,Website Visited,chrome.exe,https://internal.corp.local/intranet,Admin,Normal corporate intranet browsing
"""

@router.get("/sample-csv", response_class=PlainTextResponse)
def get_sample_csv():
    """Returns sample CSV template for testing triage."""
    return PlainTextResponse(
        content=SAMPLE_CSV_CONTENT,
        headers={"Content-Disposition": 'attachment; filename="RapidTriage_Sample_Dataset.csv"'}
    )

@router.post("/validate")
async def validate_evidence_file(file: UploadFile = File(...)):
    """
    Validates CSV or JSON file without storing.
    Returns preview rows, columns, event count, and any column validation errors.
    """
    filename = file.filename or "uploaded_dataset"
    content = await file.read()
    
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")

    sha256_hash = compute_sha256(content)

    if filename.endswith(".csv"):
        success, msg, events = parse_csv_bytes(content)
    elif filename.endswith(".json"):
        success, msg, events = parse_json_bytes(content)
    else:
        raise HTTPException(status_code=400, detail="Unsupported file format. Please upload a .csv or .json file.")

    if not success:
        return {
            "valid": False,
            "error": msg,
            "filename": filename,
            "fileSize": f"{len(content) / 1024:.1f} KB",
            "sha256": sha256_hash,
            "preview": []
        }

    preview = events[:5]
    return {
        "valid": True,
        "message": msg,
        "filename": filename,
        "fileSize": f"{len(content) / 1024:.1f} KB",
        "sha256": sha256_hash,
        "totalRecords": len(events),
        "preview": preview
    }

@router.post("/upload")
async def upload_and_analyze_evidence(
    file: UploadFile = File(...),
    case_id: Optional[str] = Form(None),
    temporal_window: int = Form(5),
    db: Session = Depends(get_db)
):
    """
    Parses, hashes, normalizes, detects rules, correlates events, calculates risk score,
    and stores all evidence in the database.
    """
    filename = file.filename or "dataset.csv"
    content = await file.read()
    
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    sha256_hash = compute_sha256(content)

    if filename.endswith(".csv"):
        success, msg, raw_events = parse_csv_bytes(content)
    elif filename.endswith(".json"):
        success, msg, raw_events = parse_json_bytes(content)
    else:
        raise HTTPException(status_code=400, detail="Unsupported file type. Use .csv or .json.")

    if not success or not raw_events:
        raise HTTPException(status_code=400, detail=msg)

    # Correlate and detect
    correlated_events, findings_list = run_correlation(raw_events, temporal_window)
    risk_score, risk_level, risk_indicators = calculate_case_risk(correlated_events, findings_list)

    # Determine Case
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    active_case_id = case_id or f"RT-UPL-{datetime.utcnow().strftime('%m%d%H%M')}"
    
    case = db.query(Case).filter(Case.id == active_case_id).first()
    if not case:
        case = Case(
            id=active_case_id,
            endpoint="MANUAL-IMPORT-PC",
            os="Imported Evidence Dataset",
            status="Requires Investigation" if risk_score > 30 else "Normal",
            acquisition_time=now_str,
            is_demo_data=False,
            risk_score=risk_score,
            risk_level=risk_level,
            notes=f"Dataset '{filename}' imported by investigator. {len(correlated_events)} events normalized and analyzed."
        )
        db.add(case)
        db.flush()
    else:
        # Clear existing events/findings for this case
        db.query(Event).filter(Event.case_id == case.id).delete()
        db.query(Finding).filter(Finding.case_id == case.id).delete()
        db.query(RiskIndicator).filter(RiskIndicator.case_id == case.id).delete()
        case.risk_score = risk_score
        case.risk_level = risk_level
        case.status = "Requires Investigation" if risk_score > 30 else "Normal"
        db.flush()

    # Record EvidenceItem
    evidence_item = EvidenceItem(
        case_id=case.id,
        artifact_type="execution",
        name=f"Manual Upload: {filename}",
        source_path=f"User Upload ({filename})",
        file_size=f"{len(content) / 1024:.1f} KB",
        sha256_hash=sha256_hash,
        extracted_events_count=len(correlated_events),
        status="Verified",
        acquisition_time=now_str
    )
    db.add(evidence_item)

    # Insert events
    for ev in correlated_events:
        db_ev = Event(
            id=ev["id"],
            case_id=case.id,
            timestamp=ev["timestamp"],
            raw_timestamp=ev.get("raw_timestamp"),
            artifact=ev["artifact"],
            event_type=ev["event_type"],
            process=ev.get("process"),
            process_id=str(ev.get("process_id", "1000")),
            path=ev.get("path"),
            user=ev.get("user", "Admin"),
            description=ev["description"],
            details=ev.get("details", {}),
            risk_status=ev.get("risk_status", "normal"),
            risk_score=ev.get("risk_score", 0),
            risk_reasons=ev.get("risk_reasons", []),
            correlation_id=ev.get("correlation_id")
        )
        db.add(db_ev)

    # Insert findings
    for f in findings_list:
        db_f = Finding(
            id=f["id"],
            case_id=case.id,
            correlation_id=f["correlation_id"],
            title=f["title"],
            description=f["description"],
            risk_score=f["risk_score"],
            priority=f.get("priority", "High Priority"),
            start_time=f["start_time"],
            end_time=f["end_time"],
            time_span=f["time_span"],
            reasons=f["reasons"],
            event_ids=f["event_ids"]
        )
        db.add(db_f)

    # Insert risk indicators
    for ind in risk_indicators:
        db_ind = RiskIndicator(
            case_id=case.id,
            title=ind["title"],
            points=ind["points"],
            description=ind["description"],
            category=ind.get("category", "Execution")
        )
        db.add(db_ind)

    db.commit()

    return {
        "success": True,
        "message": f"Successfully ingested and correlated {len(correlated_events)} events from {filename}.",
        "caseId": case.id,
        "eventsCount": len(correlated_events),
        "findingsCount": len(findings_list),
        "riskScore": risk_score,
        "riskLevel": risk_level,
        "sha256": sha256_hash
    }

@router.get("/inventory")
def get_evidence_inventory(case_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Returns evidence inventory with SHA-256 hashes and verification status."""
    query = db.query(EvidenceItem)
    if case_id:
        query = query.filter(EvidenceItem.case_id == case_id)
    items = query.all()
    return [
        {
            "id": i.id,
            "caseId": i.case_id,
            "artifact": i.artifact_type,
            "name": i.name,
            "sourcePath": i.source_path,
            "fileSize": i.file_size,
            "sha256Hash": i.sha256_hash,
            "extractedEventsCount": i.extracted_events_count,
            "status": i.status,
            "acquisitionTime": i.acquisition_time,
            "isVerified": True
        }
        for i in items
    ]
