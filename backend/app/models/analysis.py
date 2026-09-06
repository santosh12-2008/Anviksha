import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey
from app.core.database import Base

class EmailAnalysis(Base):
    __tablename__ = "email_analyses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    message_id = Column(String(255), index=True, nullable=True)
    subject = Column(String(500), nullable=True)
    sender = Column(String(255), nullable=True)
    return_path = Column(String(255), nullable=True)
    reply_to = Column(String(255), nullable=True)
    recipient = Column(String(255), nullable=True)
    date_header = Column(String(100), nullable=True)
    origin_ip = Column(String(50), index=True, nullable=True)
    origin_country = Column(String(100), nullable=True)
    origin_city = Column(String(100), nullable=True)
    origin_isp = Column(String(150), nullable=True)
    spf_status = Column(String(20), default="none")
    dkim_status = Column(String(20), default="none")
    dmarc_status = Column(String(20), default="none")
    risk_score = Column(Float, default=0.0)
    threat_level = Column(String(30), default="Safe")
    forensic_data = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
