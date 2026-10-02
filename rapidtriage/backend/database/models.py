"""
RapidTriage Database Models
SQLAlchemy ORM models for cases, evidence artifacts, events, findings, and risk indicators.
"""

from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    JSON,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Case(Base):
    __tablename__ = "cases"

    id = Column(String(64), primary_key=True, index=True) # e.g. "RT-2026-001"
    endpoint = Column(String(128), default="LAB-PC-07")
    os = Column(String(128), default="Windows 11 Pro (23H2 x64)")
    status = Column(String(64), default="Requires Investigation")
    acquisition_time = Column(String(64), default=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    created_at = Column(DateTime, default=datetime.utcnow)
    is_demo_data = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(64), default="Low")
    notes = Column(Text, default="")

    evidence_items = relationship("EvidenceItem", back_populates="case", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="case", cascade="all, delete-orphan", order_by="Event.timestamp")
    findings = relationship("Finding", back_populates="case", cascade="all, delete-orphan")
    risk_indicators = relationship("RiskIndicator", back_populates="case", cascade="all, delete-orphan")

class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type = Column(String(32), nullable=False) # 'browser', 'usb', 'execution', 'network'
    name = Column(String(128), nullable=False)
    source_path = Column(String(512), nullable=False)
    file_size = Column(String(32), default="0 KB")
    sha256_hash = Column(String(64), nullable=False)
    extracted_events_count = Column(Integer, default=0)
    status = Column(String(32), default="Verified")
    acquisition_time = Column(String(64), default=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))

    case = relationship("Case", back_populates="evidence_items")

class Event(Base):
    __tablename__ = "events"

    id = Column(String(64), primary_key=True, index=True) # e.g. "EVT-101"
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(String(32), nullable=False, index=True) # "10:30:12" or "2026-10-01 10:30:12"
    raw_timestamp = Column(String(64), nullable=True)
    artifact = Column(String(32), nullable=False, index=True) # 'browser' | 'usb' | 'execution' | 'network'
    event_type = Column(String(64), nullable=False)
    process = Column(String(128), nullable=True)
    process_id = Column(String(32), nullable=True)
    path = Column(String(512), nullable=True)
    user = Column(String(64), default="SYSTEM")
    description = Column(String(512), nullable=False)
    details = Column(JSON, default=dict)
    risk_status = Column(String(32), default="normal") # 'normal' | 'review' | 'suspicious'
    risk_score = Column(Integer, default=0)
    risk_reasons = Column(JSON, default=list) # List of string explanations
    correlation_id = Column(String(64), nullable=True, index=True) # e.g. "CORR-001"

    case = relationship("Case", back_populates="events")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, index=True) # e.g. "FND-001"
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    correlation_id = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    risk_score = Column(Integer, default=0)
    priority = Column(String(64), default="Medium Priority")
    start_time = Column(String(32), nullable=False)
    end_time = Column(String(32), nullable=False)
    time_span = Column(String(64), default="0m")
    reasons = Column(JSON, default=list)
    event_ids = Column(JSON, default=list)

    case = relationship("Case", back_populates="findings")

class RiskIndicator(Base):
    __tablename__ = "risk_indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    points = Column(Integer, default=0)
    description = Column(String(512), nullable=False)
    category = Column(String(64), default="Execution")

    case = relationship("Case", back_populates="risk_indicators")
