import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from .database import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, nullable=False)
    profile = Column(String, nullable=False)
    status = Column(String, default="running", nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, default="TCP", nullable=False)
    state = Column(String, default="open", nullable=False)
    status = Column(String, default="open", nullable=False)
    service = Column(String, nullable=True)
    banner = Column(Text, nullable=True)
    vulnerability = Column(Text, nullable=True)
    vulnerabilities = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="results")

Index("idx_scans_status", Scan.status)
Index("idx_scan_results_scan_id", ScanResult.scan_id)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=False)
    protocol = Column(String, nullable=False)
    alert_type = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)

Index("idx_alerts_timestamp", Alert.timestamp)
Index("idx_alerts_severity", Alert.severity)


class AgentSession(Base):
    __tablename__ = "agent_sessions"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, nullable=False)
    profile = Column(String, default="quick", nullable=False)
    status = Column(String, default="running", nullable=False)  # running, awaiting_approval, completed, failed
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    steps = relationship("AgentStep", back_populates="session", cascade="all, delete-orphan", order_by="AgentStep.step_number")

class AgentStep(Base):
    __tablename__ = "agent_steps"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False)
    step_number = Column(Integer, nullable=False)
    action_type = Column(String, nullable=False)  # scan, analyze, explain, investigate, remediate
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="running", nullable=False)  # running, completed, pending_approval, approved, rejected, skipped
    result_data = Column(Text, nullable=True)  # JSON serialized result
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    session = relationship("AgentSession", back_populates="steps")

Index("idx_agent_sessions_status", AgentSession.status)
Index("idx_agent_steps_session_id", AgentStep.session_id)
