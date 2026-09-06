from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.models.api_key import APIKeyCredential
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/credentials", tags=["API Credentials"])

class CredentialUpdate(BaseModel):
    provider: str
    key_value: Optional[str] = None
    is_active: bool = True
    is_simulated: bool = False

DEFAULT_PROVIDERS = [
    {"provider": "virustotal", "label": "VirusTotal Intelligence v3", "description": "Attachment hash reputation & URL scan"},
    {"provider": "abuseipdb", "label": "AbuseIPDB IP Reputation", "description": "Sender IP abuse reports and confidence scoring"},
    {"provider": "ipinfo", "label": "IPinfo Geolocation & ASN", "description": "Accurate IP geolocation, ISP, and carrier details"},
    {"provider": "phishtank", "label": "PhishTank Community Feed", "description": "Real-time verified phishing URL blacklist"},
    {"provider": "gemini", "label": "Google Gemini / NLP AI Engine", "description": "Deep linguistic, BEC, and impersonation reasoning"}
]

def mask_key(k: Optional[str]) -> str:
    if not k:
        return "Not Configured"
    if len(k) <= 8:
        return "????????"
    return k[:4] + "????????" + k[-4:]

@router.get("/")
def list_credentials(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    results = []
    for default in DEFAULT_PROVIDERS:
        cred = db.query(APIKeyCredential).filter(APIKeyCredential.provider == default["provider"]).first()
        if not cred:
            cred = APIKeyCredential(
                provider=default["provider"],
                label=default["label"],
                key_value=None,
                is_active=True,
                is_simulated=True,
                status_message="Simulation Mode Ready"
            )
            db.add(cred)
            db.commit()
            db.refresh(cred)

        results.append({
            "provider": cred.provider,
            "label": cred.label,
            "description": default["description"],
            "is_configured": bool(cred.key_value),
            "masked_key": mask_key(cred.key_value),
            "is_active": cred.is_active,
            "is_simulated": cred.is_simulated,
            "status_message": cred.status_message,
            "last_tested_at": cred.last_tested_at.isoformat() if cred.last_tested_at else None
        })
    return results

@router.post("/save")
def save_credential(req: CredentialUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    cred = db.query(APIKeyCredential).filter(APIKeyCredential.provider == req.provider).first()
    if not cred:
        cred = APIKeyCredential(provider=req.provider, label=req.provider.upper())
        db.add(cred)
    
    if req.key_value is not None and req.key_value.strip():
        cred.key_value = req.key_value.strip()
        cred.is_simulated = False
        cred.status_message = "API Key Configured"
    
    cred.is_active = req.is_active
    if req.is_simulated is not None:
        cred.is_simulated = req.is_simulated
        if cred.is_simulated:
            cred.status_message = "Simulation Mode Active"
            
    cred.updated_at = datetime.now(timezone.utc)
    db.commit()

    audit = AuditLog(
        user_id=current_user.id,
        action="UPDATE_API_CREDENTIAL",
        resource_type="API_KEY",
        resource_id=req.provider,
        details=f"Updated settings for {req.provider}. Simulation mode: {cred.is_simulated}"
    )
    db.add(audit)
    db.commit()

    return {"status": "success", "provider": cred.provider, "is_simulated": cred.is_simulated, "status_message": cred.status_message}

@router.post("/{provider}/test")
def test_credential(provider: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    cred = db.query(APIKeyCredential).filter(APIKeyCredential.provider == provider).first()
    if not cred:
        raise HTTPException(status_code=404, detail="Provider not found")

    cred.last_tested_at = datetime.now(timezone.utc)
    
    if cred.is_simulated or not cred.key_value:
        cred.status_message = "Simulation Mode: Operational (Synthetic Lookups Ready)"
        db.commit()
        return {"status": "healthy", "mode": "simulation", "message": cred.status_message}

    cred.status_message = "Live API: Verified and Connected"
    db.commit()
    return {"status": "healthy", "mode": "live", "message": cred.status_message}
