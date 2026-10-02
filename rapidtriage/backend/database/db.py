"""
RapidTriage Database Session & Initialization
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from rapidtriage.backend.config import DATABASE_URL
from rapidtriage.backend.database.models import Base, Case, EvidenceItem, Event, Finding, RiskIndicator
from rapidtriage.backend.forensic.hasher import compute_sha256

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes tables and seeds default case if database is empty."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing_case = db.query(Case).first()
        if not existing_case:
            seed_initial_case(db)
    finally:
        db.close()

def seed_initial_case(db: Session):
    """Seeds default demonstration case (RT-2026-001) as requested."""
    case = Case(
        id="RT-2026-001",
        endpoint="LAB-PC-07",
        os="Windows 11 Pro (23H2 x64)",
        status="Requires Investigation",
        acquisition_time="2026-10-01 10:45:00 UTC",
        is_demo_data=True,
        risk_score=75,
        risk_level="Elevated",
        notes="Investigator initialized triage. Browser download was swiftly followed by execution from user AppData roaming location and subsequent outbound HTTPS connection."
    )
    db.add(case)
    db.flush()

    # Evidence items
    evidence_items = [
        EvidenceItem(
            case_id=case.id,
            artifact_type="browser",
            name="Chrome / Firefox History & Downloads",
            source_path="C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
            file_size="2.4 MB",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            extracted_events_count=3,
            status="Verified",
            acquisition_time="2026-10-01 10:45:12 UTC"
        ),
        EvidenceItem(
            case_id=case.id,
            artifact_type="usb",
            name="Windows Registry (SYSTEM / NTUSER)",
            source_path="C:\\Windows\\System32\\config\\SYSTEM (Enum\\USBSTOR)",
            file_size="14.8 MB",
            sha256_hash="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            extracted_events_count=2,
            status="Verified",
            acquisition_time="2026-10-01 10:45:20 UTC"
        ),
        EvidenceItem(
            case_id=case.id,
            artifact_type="execution",
            name="Windows Prefetch & Execution Traces",
            source_path="C:\\Windows\\Prefetch\\*.pf",
            file_size="8.1 MB",
            sha256_hash="4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            extracted_events_count=3,
            status="Verified",
            acquisition_time="2026-10-01 10:45:28 UTC"
        ),
        EvidenceItem(
            case_id=case.id,
            artifact_type="network",
            name="TCP Active Table & Network Artifacts",
            source_path="C:\\Windows\\System32\\drivers\\etc\\hosts + NetTCPConnection",
            file_size="512 KB",
            sha256_hash="ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
            extracted_events_count=2,
            status="Verified",
            acquisition_time="2026-10-01 10:45:35 UTC"
        ),
    ]
    for item in evidence_items:
        db.add(item)

    # Events
    events = [
        Event(
            id="EVT-101",
            case_id=case.id,
            timestamp="10:30:12",
            raw_timestamp="2026-10-01 10:30:12",
            artifact="browser",
            event_type="Website Visited",
            process="chrome.exe",
            process_id="4120",
            path="https://dist-software-update.cc/client",
            user="Admin",
            description="Visited suspicious software distribution domain",
            details={"url": "https://dist-software-update.cc/client", "title": "Client Update Delivery Portal"},
            risk_status="normal",
            risk_score=10,
            risk_reasons=[],
            correlation_id=None
        ),
        Event(
            id="EVT-102",
            case_id=case.id,
            timestamp="10:30:18",
            raw_timestamp="2026-10-01 10:30:18",
            artifact="browser",
            event_type="File Download",
            process="chrome.exe",
            process_id="4120",
            path="C:\\Users\\Admin\\Downloads\\update.exe",
            user="Admin",
            description="Downloaded binary 'update.exe' to user Downloads directory",
            details={"file": "update.exe", "source_url": "https://dist-software-update.cc/client/update.exe"},
            risk_status="review",
            risk_score=45,
            risk_reasons=["Binary executable downloaded from unverified external origin"],
            correlation_id="CORR-001"
        ),
        Event(
            id="EVT-103",
            case_id=case.id,
            timestamp="10:32:05",
            raw_timestamp="2026-10-01 10:32:05",
            artifact="usb",
            event_type="Device Connected",
            process="SYSTEM",
            process_id="4",
            path="USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00",
            user="SYSTEM",
            description="USB Mass Storage device connected (SanDisk Ultra, Serial: 4C530001)",
            details={"vendor": "SanDisk", "serial": "4C530001091215115252", "drive_letter": "E:"},
            risk_status="review",
            risk_score=30,
            risk_reasons=["Removable USB storage connected during active browsing session"],
            correlation_id=None
        ),
        Event(
            id="EVT-104",
            case_id=case.id,
            timestamp="10:36:02",
            raw_timestamp="2026-10-01 10:36:02",
            artifact="execution",
            event_type="Process Executed",
            process="update.exe",
            process_id="5892",
            path="C:\\Users\\Admin\\AppData\\Roaming\\update.exe",
            user="Admin",
            description="Prefetch confirms execution from AppData\\Roaming directory",
            details={"prefetch_hash": "A74F9B2C", "run_count": 1, "parent_process": "explorer.exe"},
            risk_status="suspicious",
            risk_score=85,
            risk_reasons=[
                "Executed from user AppData path (Rule 1: AppData Execution)",
                "Executed within 5m44s of download (Rule 2: Download-to-Execution)"
            ],
            correlation_id="CORR-001"
        ),
        Event(
            id="EVT-105",
            case_id=case.id,
            timestamp="10:36:15",
            raw_timestamp="2026-10-01 10:36:15",
            artifact="network",
            event_type="Network Connection",
            process="update.exe",
            process_id="5892",
            path="185.220.101.45:443",
            user="Admin",
            description="Outbound TCP connection established to 185.220.101.45:443",
            details={"remote_ip": "185.220.101.45", "remote_port": 443, "protocol": "TCP", "state": "ESTABLISHED"},
            risk_status="suspicious",
            risk_score=90,
            risk_reasons=["Outbound network connection immediately initiated by AppData executable"],
            correlation_id="CORR-001"
        ),
        Event(
            id="EVT-106",
            case_id=case.id,
            timestamp="10:38:22",
            raw_timestamp="2026-10-01 10:38:22",
            artifact="execution",
            event_type="Process Executed",
            process="cmd.exe",
            process_id="6104",
            path="C:\\Windows\\System32\\cmd.exe /c whoami",
            user="Admin",
            description="Command prompt spawned to perform user discovery",
            details={"command_line": "cmd.exe /c whoami", "parent_pid": "5892"},
            risk_status="suspicious",
            risk_score=80,
            risk_reasons=["Spawned as child process of unverified executable update.exe"],
            correlation_id="CORR-001"
        ),
        Event(
            id="EVT-107",
            case_id=case.id,
            timestamp="10:40:00",
            raw_timestamp="2026-10-01 10:40:00",
            artifact="browser",
            event_type="Website Visited",
            process="chrome.exe",
            process_id="4120",
            path="https://internal.corp.local/intranet",
            user="Admin",
            description="Routine internal company intranet visit",
            details={"url": "https://internal.corp.local/intranet"},
            risk_status="normal",
            risk_score=0,
            risk_reasons=[],
            correlation_id=None
        ),
    ]
    for ev in events:
        db.add(ev)

    # Findings
    finding = Finding(
        id="FND-001",
        case_id=case.id,
        correlation_id="CORR-001",
        title="Download followed by AppData Execution and Outbound Network",
        description="Binary update.exe was downloaded via Chrome, subsequently executed from user AppData directory 5m44s later, and immediately initiated outbound network communications to 185.220.101.45:443.",
        risk_score=85,
        priority="High Priority",
        start_time="10:30:18",
        end_time="10:38:22",
        time_span="8m 4s",
        reasons=[
            "Executed from AppData directory (C:\\Users\\Admin\\AppData\\Roaming\\update.exe)",
            "Executed within 5m44s after browser download",
            "Outbound network connection immediately following execution",
            "Command line discovery spawned as child process"
        ],
        event_ids=["EVT-102", "EVT-104", "EVT-105", "EVT-106"]
    )
    db.add(finding)

    # Risk Indicators
    indicators = [
        RiskIndicator(
            case_id=case.id,
            title="Execution from User AppData Directory",
            points=30,
            description="update.exe launched from C:\\Users\\Admin\\AppData\\Roaming\\",
            category="Execution"
        ),
        RiskIndicator(
            case_id=case.id,
            title="Download-to-Execution Within 5 Minutes",
            points=25,
            description="Execution occurred 5m 44s following Chrome download",
            category="Correlation"
        ),
        RiskIndicator(
            case_id=case.id,
            title="Immediate Outbound Network Activity",
            points=20,
            description="Direct connection established to external IP 185.220.101.45:443",
            category="Network"
        ),
    ]
    for ind in indicators:
        db.add(ind)

    db.commit()
