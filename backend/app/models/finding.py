from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, Float, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.database import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    source_tool = Column(String(50))
    plugin_id = Column(String(100))
    title = Column(Text, nullable=False)
    description = Column(Text)
    severity = Column(String(20))
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    cve_id = Column(String(50))
    cwe_id = Column(String(20))
    risk_score = Column(Integer)
    priority_rank = Column(Integer)
    affected_asset = Column(String(255))
    asset_ip = Column(String(45))
    asset_hostname = Column(String(255))
    port = Column(Integer)
    protocol = Column(String(10))
    service = Column(String(50))
    evidence = Column(Text)
    remediation_guidance = Column(Text)
    effort_hours = Column(Integer)
    status = Column(String(50), default='open')
    jira_ticket_key = Column(String(50))
    jira_ticket_url = Column(Text)
    detected_date = Column(DateTime, default=datetime.utcnow)
    resolved_date = Column(DateTime)
    false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)