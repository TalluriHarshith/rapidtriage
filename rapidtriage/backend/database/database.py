"""
SQLite Database Engine & Session Management for RapidTriage
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from rapidtriage.backend.config import DATABASE_URL
from rapidtriage.backend.database.models import Base, Case, Evidence, Event, Finding, Correlation

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initializes tables and seeds baseline demo data if not exists"""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_demo_case(db)
    finally:
        db.close()


def seed_demo_case(db: Session):
    """Seeds sample case RT-2026-001 with realistic forensic records if not present"""
    existing = db.query(Case).filter(Case.case_id == "RT-2026-001").first()
    if existing:
        return

    demo_case = Case(
        case_id="RT-2026-001",
        case_name="Workstation Incident Triage",
        endpoint_name="LAB-PC-07",
        operating_system="Windows 11 Pro 23H2 (Build 22631.3296)",
        status="under_investigation",
        investigation_notes="Preliminary triage for workstation LAB-PC-07 following anomalous endpoint activity.",
    )
    db.add(demo_case)

    # 4 Standardized Evidence Packages
    evidences = [
        Evidence(
            artifact_id="EVID-001",
            case_id="RT-2026-001",
            filename="Chrome_History_Default.sqlite",
            artifact_type="browser",
            source="Chrome SQLite History",
            size="2.4 MB",
            sha256="a8f46b12d5918739cfbe451109a9042b5821c17e384d59a2394c921319c4e21a",
            acquisition_time="2026-10-02 10:45:12 UTC",
            status="verified",
            file_path="storage/evidence/RT-2026-001/Chrome_History_Default.sqlite",
        ),
        Evidence(
            artifact_id="EVID-002",
            case_id="RT-2026-001",
            filename="Registry_SYSTEM_Hive.dat",
            artifact_type="usb",
            source="Windows Registry USBSTOR",
            size="18.7 MB",
            sha256="7c89f10a23b8d64112e84179acde22105e19ff5628b0314aa78942b9104c8f20",
            acquisition_time="2026-10-02 10:45:18 UTC",
            status="verified",
            file_path="storage/evidence/RT-2026-001/Registry_SYSTEM_Hive.dat",
        ),
        Evidence(
            artifact_id="EVID-003",
            case_id="RT-2026-001",
            filename="Prefetch_Archive.tar",
            artifact_type="execution",
            source="Windows Prefetch / UserAssist",
            size="6.1 MB",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            acquisition_time="2026-10-02 10:45:25 UTC",
            status="verified",
            file_path="storage/evidence/RT-2026-001/Prefetch_Archive.tar",
        ),
        Evidence(
            artifact_id="EVID-004",
            case_id="RT-2026-001",
            filename="Netstat_Table_Dump.json",
            artifact_type="network",
            source="Active TCP Connection Table",
            size="142 KB",
            sha256="992a548f0293dbca840131498bfe192138a0bc17234918da57102948ca921133",
            acquisition_time="2026-10-02 10:45:30 UTC",
            status="verified",
            file_path="storage/evidence/RT-2026-001/Netstat_Table_Dump.json",
        ),
    ]
    for ev in evidences:
        db.add(ev)

    # Standardized Events
    events_data = [
        Event(
            event_id="EVT-101",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:28:44",
            timestamp_original="13372290524000000 (WebKit)",
            artifact="browser",
            event_type="Website Visited",
            source="Chrome SQLite History",
            user="WIN-DC892\\Admin",
            url="https://learn.microsoft.com/en-us/sysinternals/downloads/procmon",
            description="Visited Microsoft Sysinternals documentation",
            risk_status="normal",
        ),
        Event(
            event_id="EVT-102",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:29:15",
            timestamp_original="133722905550000000 (FILETIME)",
            artifact="execution",
            event_type="Process Execution",
            source="Windows Prefetch",
            user="WIN-DC892\\Admin",
            process="msedge.exe",
            file="msedge.exe",
            path="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            description="msedge.exe executed from Program Files",
            risk_status="normal",
        ),
        Event(
            event_id="EVT-103",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:30:12",
            timestamp_original="13372290612000000 (WebKit)",
            artifact="browser",
            event_type="Website Visited",
            source="Chrome SQLite History",
            user="WIN-DC892\\Admin",
            url="https://software-dist-cdn.net/portal/update.php",
            description="Visited external download portal: software-dist-cdn.net",
            risk_status="review",
        ),
        Event(
            event_id="EVT-104",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:30:18",
            timestamp_original="13372290618000000 (WebKit)",
            artifact="browser",
            event_type="File Downloaded",
            source="Chrome SQLite History",
            user="WIN-DC892\\Admin",
            process="chrome.exe",
            file="update.exe",
            path="C:\\Users\\Admin\\Downloads\\update.exe",
            url="https://software-dist-cdn.net/files/update.exe",
            description="File downloaded: update.exe",
            risk_status="review",
            correlation_id="CORR-001",
        ),
        Event(
            event_id="EVT-105",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:32:05",
            timestamp_original="1727865125 (Epoch)",
            artifact="network",
            event_type="Connection Established",
            source="Active Connections Table",
            user="NT AUTHORITY\\SYSTEM",
            process="svchost.exe",
            pid=1104,
            local_address="192.168.1.105:54210",
            remote_address="192.168.1.1:53",
            description="DNS resolution query via svchost.exe",
            risk_status="normal",
        ),
        Event(
            event_id="EVT-106",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:34:10",
            timestamp_original="133722908500000000 (FILETIME)",
            artifact="execution",
            event_type="Process Execution",
            source="Windows Prefetch",
            user="WIN-DC892\\Admin",
            process="explorer.exe",
            file="explorer.exe",
            path="C:\\Windows\\explorer.exe",
            description="Windows Explorer interactive folder access",
            risk_status="normal",
        ),
        Event(
            event_id="EVT-107",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:35:20",
            timestamp_original="133722909200000000 (FILETIME)",
            artifact="usb",
            event_type="USB Device Detected",
            source="Windows Registry (USBSTOR)",
            user="SYSTEM",
            device="Kingston DataTraveler 3.0",
            serial="0014D1237A8B",
            path="E:\\",
            description="USB device detected: Kingston DataTraveler 3.0 (Drive E:)",
            risk_status="review",
            correlation_id="CORR-001",
        ),
        Event(
            event_id="EVT-108",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:36:02",
            timestamp_original="133722909620000000 (FILETIME)",
            artifact="execution",
            event_type="Process Execution",
            source="Windows Prefetch",
            user="WIN-DC892\\Admin",
            process="update.exe",
            file="update.exe",
            path="C:\\Users\\Admin\\AppData\\Roaming\\update.exe",
            description="update.exe executed from AppData directory",
            risk_status="suspicious",
            reason="Process executed from a user AppData directory.",
            rule_flags="APPDATA_EXECUTION,DOWNLOAD_EXECUTION",
            correlation_id="CORR-001",
        ),
        Event(
            event_id="EVT-109",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:36:10",
            timestamp_original="1727865370 (Epoch)",
            artifact="network",
            event_type="Connection Established",
            source="Active Connections Table",
            user="WIN-DC892\\Admin",
            process="update.exe",
            pid=4892,
            local_address="192.168.1.105:49812",
            remote_address="185.220.101.45:443",
            description="update.exe: Outbound HTTPS connection established to 185.220.101.45:443",
            risk_status="suspicious",
            reason="Network activity initiated by process running from AppData shortly after download.",
            rule_flags="RELATED_NETWORK_ACTIVITY",
            correlation_id="CORR-001",
        ),
        Event(
            event_id="EVT-110",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:37:15",
            timestamp_original="133722910350000000 (FILETIME)",
            artifact="execution",
            event_type="UserAssist Launch Recorded",
            source="Windows Registry (UserAssist)",
            user="WIN-DC892\\Admin",
            process="update.exe",
            path="C:\\Users\\Admin\\AppData\\Roaming\\update.exe",
            description="UserAssist recorded execution count increment for update.exe",
            risk_status="review",
            correlation_id="CORR-001",
        ),
        Event(
            event_id="EVT-111",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:38:00",
            timestamp_original="1727865480 (Epoch)",
            artifact="network",
            event_type="Connection Established",
            source="Active Connections Table",
            user="WIN-DC892\\Admin",
            process="update.exe",
            pid=4892,
            local_address="192.168.1.105:49818",
            remote_address="185.220.101.45:443",
            description="update.exe: Secondary outbound socket established to 185.220.101.45:443",
            risk_status="suspicious",
            reason="Follow-up network beacon from suspicious process.",
            rule_flags="RELATED_NETWORK_ACTIVITY",
            correlation_id="CORR-001",
        ),
        Event(
            event_id="EVT-112",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:41:22",
            timestamp_original="13372291282000000 (WebKit)",
            artifact="browser",
            event_type="Website Visited",
            source="Chrome SQLite History",
            user="WIN-DC892\\Admin",
            url="https://portal.office.com/landing",
            description="Normal user browsing: Office 365 portal",
            risk_status="normal",
        ),
        Event(
            event_id="EVT-113",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:42:01",
            timestamp_original="1727865721 (Epoch)",
            artifact="network",
            event_type="Connection Established",
            source="Active Connections Table",
            user="WIN-DC892\\Admin",
            process="chrome.exe",
            pid=3204,
            local_address="192.168.1.105:50120",
            remote_address="52.96.166.130:443",
            description="chrome.exe: HTTPS connection to Microsoft cloud endpoint",
            risk_status="normal",
        ),
        Event(
            event_id="EVT-114",
            case_id="RT-2026-001",
            timestamp="2026-10-02T10:43:10",
            timestamp_original="133722913900000000 (FILETIME)",
            artifact="usb",
            event_type="USB Volume Unmounted",
            source="Windows Registry (MountedDevices)",
            user="SYSTEM",
            device="Kingston DataTraveler 3.0",
            path="E:\\",
            description="USB storage volume dismounted",
            risk_status="normal",
        ),
    ]
    for ev in events_data:
        db.add(ev)

    # Correlation CORR-001
    corr = Correlation(
        correlation_id="CORR-001",
        case_id="RT-2026-001",
        start_time="10:30:18",
        end_time="10:38:00",
        event_ids="EVT-104,EVT-107,EVT-108,EVT-109,EVT-110,EVT-111",
        reason="Browser download followed by AppData execution, USB mounting, and outbound network socket connection.",
        status="requires_investigation",
    )
    db.add(corr)

    # Finding FND-001
    fnd = Finding(
        finding_id="FND-001",
        case_id="RT-2026-001",
        rule="APPDATA_EXECUTION_DOWNLOAD_NETWORK",
        description="Download → Execution → Network",
        priority="High Investigation Priority",
        risk_score=85,
        reason="Process executed from user AppData directory shortly after external browser download, followed by outbound socket connection.",
        correlation_id="CORR-001",
        event_ids="EVT-104,EVT-107,EVT-108,EVT-109,EVT-111",
    )
    db.add(fnd)

    db.commit()
