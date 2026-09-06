import os
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import engine, Base, SessionLocal
from app.core.security import hash_password
from app.models.user import User
from app.models.api_key import APIKeyCredential
from app.models.community import CommunityAttackReport, DomainThreatReport

# Import routers
from app.api.auth import router as auth_router
from app.api.credentials import router as credentials_router
from app.api.emails import router as emails_router
from app.api.forensics import router as forensics_router
from app.api.community import router as community_router

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Seed default Admin
        if not db.query(User).filter(User.username == "admin").first():
            admin = User(
                username="admin",
                email="admin@anviksha.local",
                full_name="Chief Incident Commander",
                hashed_password=hash_password("Admin@2026!"),
                role="admin"
            )
            db.add(admin)

        # Seed default Analyst
        if not db.query(User).filter(User.username == "analyst").first():
            analyst = User(
                username="analyst",
                email="analyst@anviksha.local",
                full_name="SOC Threat Hunter",
                hashed_password=hash_password("Analyst@2026!"),
                role="analyst"
            )
            db.add(analyst)

        # Pre-seed API credentials in simulation mode
        default_providers = [
            ("virustotal", "VirusTotal Intelligence v3", "Attachment hash reputation & URL maliciousness check"),
            ("abuseipdb", "AbuseIPDB IP Reputation", "Sender IP abuse reports and confidence scoring"),
            ("ipinfo", "IPinfo Geolocation & ASN", "Accurate IP geolocation, ISP, and carrier details"),
            ("phishtank", "PhishTank Community Feed", "Real-time verified phishing URL blacklist"),
            ("gemini", "Google Gemini / NLP AI Engine", "Deep linguistic, BEC, and impersonation reasoning")
        ]
        for prov, label, desc in default_providers:
            if not db.query(APIKeyCredential).filter(APIKeyCredential.provider == prov).first():
                cred = APIKeyCredential(
                    provider=prov,
                    label=label,
                    key_value=None,
                    is_active=True,
                    is_simulated=True,
                    status_message="Simulation Mode Active (Synthetic Threat Intel Ready)"
                )
                db.add(cred)

        # Pre-seed realistic community attack stories so users see experiences immediately
        if db.query(CommunityAttackReport).count() == 0:
            sample_stories = [
                CommunityAttackReport(
                    author_name="Priya M. (Senior Accountant)",
                    target_industry="Accounting & Corporate Finance",
                    email_subject="Urgent: Your PayPal Account Has Been Temporarily Limited",
                    sender_domain="paypal-security-auth.com",
                    threat_category="Credential Phishing / Account Takeover",
                    story="Received this exact email on Tuesday morning claiming my account would be locked in 24 hours. The logo looked 100% genuine. I almost clicked the link, but noticed the URL had 'paypal-security-auth.com' instead of 'paypal.com'. When checked in Anviksha, the origin IP was an anonymous Tor node in Frankfurt, Germany. Saved our department from account compromise!",
                    financial_loss="$0 (Detected in time)",
                    warning_signs=json.dumps([
                        "Artificial 24-hour urgency countdown",
                        "Lookalike domain containing 'auth' and 'security'",
                        "Generic greeting without customer name",
                        "Failed SPF & DMARC authentication"
                    ]),
                    prevention_advice="Always hover over links to inspect the actual destination domain. Real financial institutions never host login portals on third-party domains.",
                    likes_count=42
                ),
                CommunityAttackReport(
                    author_name="Marcus K. (Operations Director)",
                    target_industry="Logistics & Supply Chain",
                    email_subject="Strictly Confidential: Urgent Payment Diversion Request",
                    sender_domain="spectranet.com.ng",
                    threat_category="Business Email Compromise (BEC)",
                    story="An email arrived seemingly from our CEO stating he was in an executive meeting and needed an urgent vendor wire payment processed before market close. Our junior controller was about to authorize $48,000 when Anviksha flagged the Nigerian ISP origin and SPF mismatch. We called the CEO directly — he had sent nothing!",
                    financial_loss="$48,000 Saved",
                    warning_signs=json.dumps([
                        "'Strictly Confidential - Do not call me' cue",
                        "Request to change beneficiary bank routing details",
                        "Originating server located in Nigeria (Spectranet ISP)",
                        "Reply-To address differed from CEO's real email"
                    ]),
                    prevention_advice="Mandate two-person out-of-band phone authorization for any wire transfer or payment diversion, no matter how urgent.",
                    likes_count=89
                ),
                CommunityAttackReport(
                    author_name="Elena R. (Cybersecurity Admin)",
                    target_industry="Higher Education & Tech",
                    email_subject="Critical Update: Re-authenticate Microsoft 365 MFA Token (Scan QR Code)",
                    sender_domain="microsoft-auth-verify.xyz",
                    threat_category="Quishing (QR Code Phishing)",
                    story="A sophisticated QR phishing lure targeted 150 staff members. Because traditional email gateways couldn't read the image text, it slipped past our spam filter. Anviksha detected the Quishing pattern and flagged the suspicious '.xyz' domain and Tor relay before users scanned it on their personal phones.",
                    financial_loss="$0 (Blocked at perimeter)",
                    warning_signs=json.dumps([
                        "QR code embedded to bypass text-based spam inspection",
                        "Prompting user to switch from protected PC to mobile phone",
                        "Deceptive '.xyz' domain instead of microsoft.com",
                        "Threat of OneDrive suspension"
                    ]),
                    prevention_advice="Train staff that IT administrators will never email a QR code asking to re-authenticate login credentials.",
                    likes_count=67
                )
            ]
            for s in sample_stories:
                db.add(s)

        # Pre-seed community reported domains
        if db.query(DomainThreatReport).count() == 0:
            sample_domains = [
                DomainThreatReport(
                    domain_or_email="paypal-security-auth.com",
                    threat_type="Phishing / Brand Lookalike",
                    description="Active credential harvesting phishing portal masquerading as PayPal Resolution Center.",
                    evidence_snippet="Hosted on Tor exit node 185.220.101.5 with forged Return-Path.",
                    reported_by="Analyst Priya",
                    status="Confirmed Malicious"
                ),
                DomainThreatReport(
                    domain_or_email="dhl-express-tracking24.net",
                    threat_type="Malware Dropper",
                    description="Distributes double-extension Trojan (.pdf.exe) via fake clearance fee notices.",
                    evidence_snippet="Originating from Russian bulletproof hosting relay 194.26.29.112.",
                    reported_by="Marcus K.",
                    status="Confirmed Malicious"
                ),
                DomainThreatReport(
                    domain_or_email="microsoft-auth-verify.xyz",
                    threat_type="Quishing Vector",
                    description="Hosts mobile credential interception proxy targeting Microsoft 365 MFA tokens.",
                    evidence_snippet="QR code redirects to reverse-proxy harvesting session cookies.",
                    reported_by="Elena SOC",
                    status="Under Review"
                )
            ]
            for d in sample_domains:
                db.add(d)

        db.commit()
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="Anviksha (अन्वीक्षा) - Cognitive Email Forensics Platform",
    description="AI-Powered Email Threat Detection, Origin Geolocation & Deep Forensic Intelligence Platform",
    version="2.5.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(credentials_router, prefix=settings.API_V1_STR)
app.include_router(emails_router, prefix=settings.API_V1_STR)
app.include_router(forensics_router, prefix=settings.API_V1_STR)
app.include_router(community_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "Anviksha (अन्वीक्षा) Cognitive Email Forensics Platform",
        "tagline": "AI-Powered Email Threat Detection, Geolocation & Deep Forensic Intelligence",
        "api_docs": "/docs",
        "version": "2.5.0"
    }

@app.get("/api/samples/{sample_name}")
def get_sample_email(sample_name: str):
    valid_samples = {
        "phishing_paypal": "phishing_paypal.eml",
        "bec_wire_fraud": "bec_wire_fraud.eml",
        "dhl_trojan_delivery": "dhl_trojan_delivery.eml",
        "quishing_mfa_update": "quishing_mfa_update.eml",
        "hr_payroll_suspicious": "hr_payroll_suspicious.eml",
        "github_security_alert": "github_security_alert.eml",
        "legitimate_report": "legitimate_report.eml"
    }
    if sample_name not in valid_samples:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    sample_file = os.path.join(os.path.dirname(__file__), "samples", valid_samples[sample_name])
    if not os.path.exists(sample_file):
        raise HTTPException(status_code=404, detail="Sample file missing")
    
    with open(sample_file, "r", encoding="utf-8") as f:
        return {"sample_name": sample_name, "raw_content": f.read()}
