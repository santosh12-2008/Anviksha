import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from app.core.database import Base

class CommunityAttackReport(Base):
    __tablename__ = "community_attack_reports"

    id = Column(Integer, primary_key=True, index=True)
    author_name = Column(String(150), default="Anonymous Defender")
    target_industry = Column(String(100), default="General / Consumer")
    email_subject = Column(String(500), nullable=False)
    sender_domain = Column(String(255), index=True, nullable=True)
    threat_category = Column(String(100), nullable=False)  # Phishing, BEC, Quishing, Fake Invoice, Ransomware
    story = Column(Text, nullable=False)
    financial_loss = Column(String(100), default="$0 (Prevented)")
    warning_signs = Column(Text, default="[]")  # JSON list of red flags
    prevention_advice = Column(Text, nullable=True)
    likes_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class DomainThreatReport(Base):
    __tablename__ = "domain_threat_reports"

    id = Column(Integer, primary_key=True, index=True)
    domain_or_email = Column(String(255), index=True, nullable=False)
    threat_type = Column(String(100), nullable=False)  # Phishing, Spoofing, Malware, Scam, Lookalike
    description = Column(Text, nullable=False)
    evidence_snippet = Column(Text, nullable=True)
    reported_by = Column(String(150), default="Guest User")
    status = Column(String(50), default="Under Review")  # Under Review, Confirmed Malicious, Remediated
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
