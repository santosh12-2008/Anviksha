from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.core.database import Base

class APIKeyCredential(Base):
    __tablename__ = "api_credentials"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(50), unique=True, index=True, nullable=False)
    label = Column(String(100), nullable=False)
    key_value = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    is_simulated = Column(Boolean, default=True)
    last_tested_at = Column(DateTime, nullable=True)
    status_message = Column(String(255), default="Simulation Mode Active")
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
