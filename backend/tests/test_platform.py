import pytest
import os
from app.core.database import SessionLocal, Base, engine
from app.core.security import hash_password, verify_password, create_access_token, decode_access_token
from app.models.user import User
from app.models.analysis import EmailAnalysis
from app.services.email_parser import parse_email_content
from app.services.nlp_detector import analyze_text_nlp
from app.services.ioc_scanner import analyze_domain_intelligence, analyze_attachments
from app.api.emails import run_forensic_pipeline, batch_scan_inbox
from app.api.forensics import export_forensic_report
from app.api.community import get_community_reports, match_similar_experiences, report_domain_threat, DomainReportCreate

def test_password_and_jwt():
    pw = "SuperSecret#2026"
    hashed = hash_password(pw)
    assert verify_password(pw, hashed) is True

    token = create_access_token({"sub": "testanalyst", "role": "analyst"})
    decoded = decode_access_token(token)
    assert decoded["sub"] == "testanalyst"

def test_nlp_detection_and_ai_summary():
    urgent_text = "URGENT ACTION REQUIRED: wire transfer payment diversion immediately within 24 hours"
    res = analyze_text_nlp("Account Alert", urgent_text)
    assert res["nlp_score"] > 40
    assert any("Urgency" in c for c in res["flagged_categories"])
    assert "ai_summary" in res
    assert res["ai_summary"]["theme"] != ""
    assert res["ai_summary"]["executive_tldr"] != ""

def test_domain_intelligence():
    intel = analyze_domain_intelligence("paypal-security-auth.com")
    assert intel["is_lookalike"] is True
    assert intel["impersonated_brand"] == "paypal"
    assert intel["threat_score"] > 80

def test_pipeline_two_tier_report():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    sample_path = os.path.join(os.path.dirname(__file__), "..", "app", "samples", "phishing_paypal.eml")
    with open(sample_path, "rb") as f:
        raw_eml = f.read()

    dossier = run_forensic_pipeline(raw_eml, db)
    analysis_id = dossier["id"]

    # Verify threat color & two-tier report
    assert dossier["threat_color"] in ["red", "yellow", "blue"]
    assert "user_friendly_report" in dossier
    assert "danger_verdict" in dossier["user_friendly_report"]
    assert len(dossier["user_friendly_report"]["action_steps"]) > 0
    assert len(dossier["predictive_faqs"]) > 0

    mock_user = User(id=1, username="test_analyst", full_name="Forensic Investigator", role="analyst")
    response = export_forensic_report(analysis_id=analysis_id, format="html", db=db, current_user=mock_user)
    db.close()

    assert response.status_code == 200
    assert "DIGITAL FORENSIC EVIDENCE REPORT" in response.body.decode("utf-8")

def test_batch_inbox_scanner():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    result = batch_scan_inbox(payload=None, db=db, current_user=None)
    db.close()

    assert result["total"] >= 5
    assert result["red_count"] > 0
    assert result["blue_count"] > 0
    assert result["red_count"] + result["yellow_count"] + result["blue_count"] == result["total"]
    print(f"Batch scan telemetry: Red={result['red_count']}, Yellow={result['yellow_count']}, Blue={result['blue_count']}, Total={result['total']}")

def test_community_matching_and_domain_reporting():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Match similar experiences
    matches = match_similar_experiences(subject="PayPal", domain="paypal-security-auth.com", category="Phishing", db=db)
    assert isinstance(matches, list)

    # Report a domain
    rep_res = report_domain_threat(
        DomainReportCreate(
            domain_or_email="suspicious-test-scam.xyz",
            threat_type="Phishing",
            description="Testing automated domain threat intelligence submission",
            reported_by="PyTest Bot"
        ),
        db=db
    )
    assert rep_res["id"] is not None
    db.close()

def test_attachment_quishing_and_double_extension():
    attachments = [
        {"filename": "Invoice_Aug_2026.pdf.exe", "size": 1048576, "content_type": "application/x-dosexec"},
        {"filename": "microsoft_mfa_qr_code.png", "size": 45120, "content_type": "image/png"},
        {"filename": "Annual_Report.pdf", "size": 250000, "content_type": "application/pdf"}
    ]
    analyzed = analyze_attachments(attachments)
    assert len(analyzed) == 3
    # First is double extension dangerous
    assert analyzed[0]["is_double_extension"] is True
    assert analyzed[0]["is_dangerous_extension"] is True
    # Second is QR quishing vector
    assert analyzed[1]["is_qr_code"] is True
    assert analyzed[1]["is_dangerous_extension"] is True
    # Third is clean
    assert analyzed[2]["is_dangerous_extension"] is False
    assert "Clean" in analyzed[2]["vt_score"]

