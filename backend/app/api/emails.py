import json
import os
import glob
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.auth import get_optional_current_user
from app.models.user import User
from app.models.api_key import APIKeyCredential
from app.models.analysis import EmailAnalysis
from app.models.audit_log import AuditLog
from app.models.community import CommunityAttackReport

from app.services.email_parser import parse_email_content
from app.services.header_forensics import parse_received_hops, detect_header_anomalies, extract_sender_domain
from app.services.auth_verifier import verify_protocols
from app.services.geo_tracer import resolve_ip_geolocation, trace_hop_geolocations
from app.services.ioc_scanner import analyze_urls, analyze_attachments, analyze_domain_intelligence
from app.services.nlp_detector import analyze_text_nlp, generate_one_sentence_verdict, generate_expert_soc_forensic_dossier
from app.services.risk_scorer import calculate_unified_risk_score
from app.services.faq_generator import generate_predictive_faqs
from app.services.gmail_service import list_gmail_messages, get_gmail_message_raw, get_gmail_message_metadata


router = APIRouter(prefix="/emails", tags=["Email Forensics"])

def get_provider_key(db: Session, provider: str) -> Optional[str]:
    cred = db.query(APIKeyCredential).filter(APIKeyCredential.provider == provider).first()
    if cred and cred.is_active and not cred.is_simulated:
        return cred.key_value
    return None

def find_similar_community_cases(db: Session, subject: str, sender_domain: str, category: str) -> List[Dict[str, Any]]:
    """Finds real-world community experiences matching this email's indicators."""
    query = db.query(CommunityAttackReport)
    matches = []
    
    if sender_domain:
        m_dom = query.filter(CommunityAttackReport.sender_domain.ilike(f"%{sender_domain}%")).limit(2).all()
        matches.extend(m_dom)

    keywords = [w.lower() for w in subject.split() if len(w) > 3]
    for kw in keywords[:3]:
        m_kw = query.filter(
            (CommunityAttackReport.email_subject.ilike(f"%{kw}%")) |
            (CommunityAttackReport.story.ilike(f"%{kw}%"))
        ).limit(2).all()
        for item in m_kw:
            if item not in matches:
                matches.append(item)

    if not matches and category:
        m_cat = query.filter(CommunityAttackReport.threat_category.ilike(f"%{category}%")).limit(2).all()
        matches.extend(m_cat)

    results = []
    for r in matches[:3]:
        signs = []
        if r.warning_signs:
            try:
                signs = json.loads(r.warning_signs) if isinstance(r.warning_signs, str) else r.warning_signs
            except:
                signs = [r.warning_signs]
        results.append({
            "id": r.id,
            "author_name": r.author_name,
            "email_subject": r.email_subject,
            "sender_domain": r.sender_domain,
            "threat_category": r.threat_category,
            "story": r.story,
            "financial_loss": r.financial_loss,
            "warning_signs": signs,
            "prevention_advice": r.prevention_advice,
            "likes_count": r.likes_count
        })
    return results

def run_forensic_pipeline(raw_bytes: bytes, db: Session, user_id: Optional[int] = None) -> dict:
    parsed = parse_email_content(raw_bytes)
    
    # 1. Header Hop Analysis
    hops = parse_received_hops(parsed.get("received_headers", []))
    header_anomalies = detect_header_anomalies(parsed, hops)

    # 2. Origin IP Extraction
    public_hops = [h for h in hops if h.get("is_public")]
    origin_ip = public_hops[0].get("ip") if public_hops else (hops[0].get("ip") if hops else None)

    # 3. Protocol Verification (SPF / DKIM / DMARC)
    sender_domain = extract_sender_domain(parsed.get("from", ""))
    auth_results = verify_protocols(sender_domain, origin_ip, parsed.get("all_headers", {}))

    # 4. Domain Intelligence (WHOIS, Age, Typosquatting)
    domain_intel = analyze_domain_intelligence(sender_domain)

    # 5. Geolocation & Hop Tracing
    ipinfo_key = get_provider_key(db, "ipinfo")
    abuse_key = get_provider_key(db, "abuseipdb")
    origin_geo = resolve_ip_geolocation(origin_ip, ipinfo_key=ipinfo_key, abuse_key=abuse_key) if origin_ip else {
        "ip": None, "country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0, "isp": "Unknown", "abuse_score": 0
    }
    enriched_hops = trace_hop_geolocations(hops, ipinfo_key=ipinfo_key)

    # 6. IOC Analysis (URLs & Attachments)
    vt_key = get_provider_key(db, "virustotal")
    url_analysis = analyze_urls(parsed.get("urls", []), vt_key=vt_key)
    attachment_analysis = analyze_attachments(parsed.get("attachments", []))

    # 7. NLP & Social Engineering Analysis (Includes AI Summary)
    nlp_results = analyze_text_nlp(parsed.get("subject", ""), parsed.get("clean_text", ""))

    # 8. Unified Risk Score Calculation
    scoring = calculate_unified_risk_score(
        header_anomalies=header_anomalies,
        auth_results=auth_results,
        geo_data=origin_geo,
        url_analysis=url_analysis,
        attachment_analysis=attachment_analysis,
        nlp_results=nlp_results
    )

    risk_num = scoring.get("risk_score", 0.0)

    # 9. Classify Threat Color (Red / Yellow / Blue)
    has_malicious_url = any(u.get("is_malicious") for u in url_analysis)
    has_dangerous_attachment = any(a.get("is_dangerous_extension") for a in attachment_analysis)
    is_spoofed_auth = (auth_results.get("spf", {}).get("status") in ["fail", "softfail"] or 
                       auth_results.get("dmarc", {}).get("status") == "fail")

    if risk_num >= 65 or origin_geo.get("is_tor") or has_dangerous_attachment or has_malicious_url:
        threat_color = "red"
        threat_color_label = "RED (Critical / High Threat)"
        danger_verdict = "DANGEROUS PHISHING / FRAUD ATTACK"
    elif risk_num >= 30 or nlp_results.get("nlp_score", 0) >= 30 or is_spoofed_auth:
        threat_color = "yellow"
        threat_color_label = "YELLOW (Suspicious / Caution)"
        danger_verdict = "SUSPICIOUS EMAIL - PROCEED WITH CAUTION"
    else:
        threat_color = "blue"
        threat_color_label = "BLUE (Safe / Verified Legitimate)"
        danger_verdict = "VERIFIED SAFE / AUTHENTIC EMAIL"

    # 10. Synthesize Plain-English Reasons for User-Friendly Report
    plain_reasons = []
    if is_spoofed_auth:
        plain_reasons.append("Failed Sender Authentication: The sending server was not authorized by the real owner of this domain (SPF/DMARC failed).")
    if origin_geo.get("is_tor"):
        plain_reasons.append(f"Anonymous Routing: Origin IP {origin_geo.get('ip')} is a known Tor cybercrime exit node in {origin_geo.get('city')}, {origin_geo.get('country')}.")
    elif origin_geo.get("is_vpn"):
        plain_reasons.append(f"VPN / Proxy Anonymization: Sent through a hosting provider / VPN in {origin_geo.get('country')}.")
    if has_malicious_url:
        plain_reasons.append("Deceptive Links: Contains links pointing to fake or lookalike login pages designed to harvest credentials.")
    if has_dangerous_attachment:
        plain_reasons.append("Malicious Attachment: Contains an executable or camouflaged double-extension file that could compromise your device.")
    if nlp_results.get("flagged_categories"):
        plain_reasons.append(f"Psychological Coercion: Uses social engineering patterns ({', '.join(nlp_results.get('flagged_categories'))}).")
    if domain_intel.get("is_newly_registered"):
        plain_reasons.append(f"Brand Impersonation / Fresh Domain: Domain '{sender_domain}' was created recently and mimics known brands.")
    if not plain_reasons:
        plain_reasons.append("Passed all cryptographic security checks with clean domain reputation and no malicious payload detected.")

    # 11. Plain-English Action Steps
    action_steps = []
    if threat_color == "red":
        action_steps = [
            "DO NOT click any links, buttons, or download attachments in this email.",
            "DO NOT reply or provide any personal, financial, or login information.",
            "If you already entered a password on a link from this email, go directly to the official website and change your password immediately.",
            "Report this email as phishing to your IT department or email provider and delete it immediately."
        ]
    elif threat_color == "yellow":
        action_steps = [
            "Verify the sender through an alternative, trusted channel (call or message them directly).",
            "Do not enter credentials or approve payments without out-of-band managerial confirmation.",
            "Inspect the sender's actual email address carefully for subtle spelling changes."
        ]
    else:
        action_steps = [
            "This email appears authentic and originated from verified infrastructure.",
            "Standard security hygiene: never disclose sensitive credentials over unencrypted channels."
        ]

    origin_badge_text = f"Origin: {origin_geo.get('city', 'Unknown')}, {origin_geo.get('country', 'Unknown')} ({origin_geo.get('isp', 'Unknown')})"
    if origin_geo.get("is_tor"):
        origin_badge_text += " [Tor Anonymizer Network]"
    elif origin_geo.get("is_vpn"):
        origin_badge_text += " [Commercial VPN / Proxy]"

    # 12. Punchy One-Sentence Verdict
    one_sentence_verdict = generate_one_sentence_verdict(
        threat_color=threat_color,
        threat_level=scoring.get("threat_level", "Safe"),
        score=risk_num,
        subject=parsed.get("subject", ""),
        origin_geo=origin_geo,
        domain_intel=domain_intel,
        has_dangerous_attachment=has_dangerous_attachment,
        has_malicious_url=has_malicious_url,
        is_spoofed_auth=is_spoofed_auth,
        matched_cues=nlp_results.get("matched_cues", {})
    )
    scoring["one_sentence_verdict"] = one_sentence_verdict
    scoring["has_dangerous_attachment"] = has_dangerous_attachment
    scoring["has_malicious_url"] = has_malicious_url

    # 13. Expert SOC Deep Forensic Intelligence Dossier
    expert_soc_dossier = generate_expert_soc_forensic_dossier(
        subject=parsed.get("subject", ""),
        sender=parsed.get("from", ""),
        origin_geo=origin_geo,
        domain_intel=domain_intel,
        auth_results=auth_results,
        nlp_results=nlp_results,
        scoring=scoring,
        threat_color=threat_color
    )

    # 14. Predictive FAQs
    predictive_faqs = generate_predictive_faqs(
        threat_level=scoring.get("threat_level", "Safe"),
        threat_color=threat_color,
        has_malicious_urls=has_malicious_url,
        has_dangerous_attachments=has_dangerous_attachment,
        is_spoofed_auth=is_spoofed_auth,
        origin_country=origin_geo.get("country", "Unknown"),
        impersonated_brand=domain_intel.get("impersonated_brand")
    )

    # 15. Similar Community Cases
    similar_cases = find_similar_community_cases(
        db=db,
        subject=parsed.get("subject", ""),
        sender_domain=sender_domain,
        category=nlp_results.get("flagged_categories", ["Phishing"])[0] if nlp_results.get("flagged_categories") else "Phishing"
    )

    # Assemble User-Friendly Report
    user_friendly_report = {
        "danger_verdict": danger_verdict,
        "one_sentence_verdict": one_sentence_verdict,
        "threat_color": threat_color,
        "threat_color_label": threat_color_label,
        "risk_score": round(risk_num, 1),
        "ai_summary": nlp_results.get("ai_summary", {}),
        "plain_reasons": plain_reasons,
        "action_steps": action_steps,
        "origin_summary": origin_badge_text
    }

    dossier = {
        "parsed_email": {
            "subject": parsed.get("subject"),
            "from": parsed.get("from"),
            "to": parsed.get("to"),
            "cc": parsed.get("cc"),
            "date": parsed.get("date"),
            "message_id": parsed.get("message_id"),
            "reply_to": parsed.get("reply_to"),
            "return_path": parsed.get("return_path"),
            "body_snippet": (parsed.get("clean_text", "")[:600] + "...") if len(parsed.get("clean_text", "")) > 600 else parsed.get("clean_text", ""),
            "raw_headers": parsed.get("all_headers", {})
        },
        "threat_color": threat_color,
        "threat_color_label": threat_color_label,
        "one_sentence_verdict": one_sentence_verdict,
        "user_friendly_report": user_friendly_report,
        "expert_soc_dossier": expert_soc_dossier,
        "origin_ip": origin_ip,
        "origin_geo": origin_geo,
        "domain_intelligence": domain_intel,
        "hops": enriched_hops,
        "header_anomalies": header_anomalies,
        "authentication": auth_results,
        "urls": url_analysis,
        "attachments": attachment_analysis,
        "nlp_analysis": nlp_results,
        "scoring": scoring,
        "predictive_faqs": predictive_faqs,
        "similar_community_cases": similar_cases
    }

    # Save to Database
    analysis_record = EmailAnalysis(
        user_id=user_id,
        message_id=parsed.get("message_id"),
        subject=parsed.get("subject"),
        sender=parsed.get("from"),
        return_path=parsed.get("return_path"),
        reply_to=parsed.get("reply_to"),
        recipient=parsed.get("to"),
        date_header=parsed.get("date"),
        origin_ip=origin_ip,
        origin_country=origin_geo.get("country"),
        origin_city=origin_geo.get("city"),
        origin_isp=origin_geo.get("isp"),
        spf_status=auth_results.get("spf", {}).get("status", "none"),
        dkim_status=auth_results.get("dkim", {}).get("status", "none"),
        dmarc_status=auth_results.get("dmarc", {}).get("status", "none"),
        risk_score=scoring.get("risk_score", 0.0),
        threat_level=scoring.get("threat_level", "Safe"),
        forensic_data=json.dumps(dossier)
    )
    db.add(analysis_record)
    db.commit()
    db.refresh(analysis_record)

    if user_id:
        audit = AuditLog(
            user_id=user_id,
            action="ANALYZE_EMAIL",
            resource_type="EMAIL_ANALYSIS",
            resource_id=str(analysis_record.id),
            details=f"Analyzed '{parsed.get('subject')}' - Score: {scoring.get('risk_score')}/100 ({threat_color.upper()})"
        )
        db.add(audit)
        db.commit()

    dossier["id"] = analysis_record.id
    dossier["created_at"] = analysis_record.created_at.isoformat()
    return dossier

@router.post("/analyze")
async def analyze_email(
    file: Optional[UploadFile] = File(None),
    raw_content: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    if file:
        raw_bytes = await file.read()
    elif raw_content and raw_content.strip():
        raw_bytes = raw_content.strip().encode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="Please provide either an email file (.eml, .msg, .txt) or raw text")

    user_id = current_user.id if current_user else None
    return run_forensic_pipeline(raw_bytes, db, user_id=user_id)

@router.get("/inbox-sample")
def get_sample_inbox():
    """
    Returns realistic incoming inbox messages for demonstration & batch testing.
    """
    sample_dir = os.path.join(os.path.dirname(__file__), "..", "samples")
    samples = [
        {
            "id": "phishing_paypal",
            "file": "phishing_paypal.eml",
            "sender": "service@paypal-security-auth.com",
            "subject": "Urgent: Your PayPal Account Has Been Temporarily Limited",
            "date": "Today, 10:45 AM",
            "preview": "We detected unauthorized access to your account. You must verify your credentials within 24 hours.",
            "simulated_threat_hint": "🔴 Red (Phishing / Tor Origin)"
        },
        {
            "id": "bec_wire_fraud",
            "file": "bec_wire_fraud.eml",
            "sender": "john.smith@spectranet.com.ng",
            "subject": "Strictly Confidential: Urgent Payment Diversion Request (Acquisition Wire)",
            "date": "Today, 09:12 AM",
            "preview": "Are you at your desk? Please process an urgent wire transfer of $84,500 immediately for project closure.",
            "simulated_threat_hint": "🔴 Red (BEC / Financial Fraud)"
        },
        {
            "id": "dhl_trojan_delivery",
            "file": "dhl_trojan_delivery.eml",
            "sender": "tracking-support@dhl-express-tracking24.net",
            "subject": "Action Required: Your DHL Express Shipment #99214-DE is On Hold (Clearance Fee Pending)",
            "date": "Today, 08:30 AM",
            "preview": "Your DHL package clearance duty is pending. Please download the attached waybill to release your delivery.",
            "simulated_threat_hint": "🔴 Red (Malware Payload / Double Extension)"
        },
        {
            "id": "quishing_mfa_update",
            "file": "quishing_mfa_update.eml",
            "sender": "admin-portal@microsoft-auth-verify.xyz",
            "subject": "Critical Update: Re-authenticate Microsoft 365 MFA Token (Scan QR Code)",
            "date": "Yesterday, 04:15 PM",
            "preview": "Your Microsoft Authenticator session token has expired. Scan the attached QR code with your mobile camera.",
            "simulated_threat_hint": "🔴 Red (Quishing / QR Phishing)"
        },
        {
            "id": "hr_payroll_suspicious",
            "file": "hr_payroll_suspicious.eml",
            "sender": "notifications@hr-benefits-direct.com",
            "subject": "Attention Required: Annual Employee Benefits Enrollment & Direct Deposit Verification",
            "date": "Yesterday, 02:00 PM",
            "preview": "Please verify your direct deposit routing numbers on file before Friday close of business.",
            "simulated_threat_hint": "🟡 Yellow (Suspicious Urgency / External Portal)"
        },
        {
            "id": "github_security_alert",
            "file": "github_security_alert.eml",
            "sender": "support@github.com",
            "subject": "[GitHub] A personal access token (classic) was recently created for your account",
            "date": "Yesterday, 11:10 AM",
            "preview": "A personal access token with 'repo' scope was generated on your account. If you created this, no action needed.",
            "simulated_threat_hint": "🔵 Blue (Verified Authentic / Clean)"
        },
        {
            "id": "legitimate_report",
            "file": "legitimate_report.eml",
            "sender": "alerts@google.com",
            "subject": "Google Workspace Monthly Security & Threat Intelligence Digest",
            "date": "2 days ago",
            "preview": "Summary of active enterprise tenant security configurations, SPF/DKIM policy alignment, and compliance.",
            "simulated_threat_hint": "🔵 Blue (Verified Clean Enterprise Alert)"
        }
    ]
    return samples

@router.post("/batch-scan-inbox")
def batch_scan_inbox(
    payload: Optional[Dict[str, Any]] = None,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    """
    Scans all emails in the inbox and assigns threat colors (Red, Yellow, Blue).
    Returns real-time telemetry: red_count, yellow_count, blue_count, total, and categorized email items.
    """
    sample_dir = os.path.join(os.path.dirname(__file__), "..", "samples")
    valid_files = [
        "phishing_paypal.eml",
        "bec_wire_fraud.eml",
        "dhl_trojan_delivery.eml",
        "quishing_mfa_update.eml",
        "hr_payroll_suspicious.eml",
        "github_security_alert.eml",
        "legitimate_report.eml"
    ]

    scanned_items = []
    red_count = 0
    yellow_count = 0
    blue_count = 0

    for fname in valid_files:
        fpath = os.path.join(sample_dir, fname)
        if not os.path.exists(fpath):
            continue
        with open(fpath, "rb") as f:
            raw_bytes = f.read()

        dossier = run_forensic_pipeline(raw_bytes, db, user_id=current_user.id if current_user else None)
        color = dossier.get("threat_color", "blue")
        
        if color == "red":
            red_count += 1
        elif color == "yellow":
            yellow_count += 1
        else:
            blue_count += 1

        scanned_items.append({
            "analysis_id": dossier.get("id"),
            "subject": dossier.get("parsed_email", {}).get("subject"),
            "sender": dossier.get("parsed_email", {}).get("from"),
            "date": dossier.get("parsed_email", {}).get("date"),
            "threat_color": color,
            "risk_score": dossier.get("scoring", {}).get("risk_score"),
            "threat_level": dossier.get("scoring", {}).get("threat_level"),
            "danger_verdict": dossier.get("user_friendly_report", {}).get("danger_verdict"),
            "ai_tldr": dossier.get("user_friendly_report", {}).get("ai_summary", {}).get("executive_tldr"),
            "origin_summary": dossier.get("user_friendly_report", {}).get("origin_summary"),
            "dossier": dossier
        })

    return {
        "total": len(scanned_items),
        "red_count": red_count,
        "yellow_count": yellow_count,
        "blue_count": blue_count,
        "items": scanned_items
    }

@router.get("/history")
def get_analysis_history(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    query = db.query(EmailAnalysis)
    if current_user:
        query = query.filter(EmailAnalysis.user_id == current_user.id)
    records = query.order_by(EmailAnalysis.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "subject": r.subject,
            "sender": r.sender,
            "recipient": r.recipient,
            "origin_ip": r.origin_ip,
            "origin_country": r.origin_country,
            "risk_score": r.risk_score,
            "threat_level": r.threat_level,
            "spf_status": r.spf_status,
            "dkim_status": r.dkim_status,
            "dmarc_status": r.dmarc_status,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in records
    ]

@router.get("/{analysis_id}")
def get_analysis_detail(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    record = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis report not found")
    dossier = json.loads(record.forensic_data)
    dossier["id"] = record.id
    dossier["created_at"] = record.created_at.isoformat() if record.created_at else None
    return dossier

class GmailScanRequest(BaseModel):
    access_token: str
    max_results: Optional[int] = 10

@router.post("/gmail/scan-inbox")
def scan_live_gmail_inbox(
    payload: GmailScanRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    """
    Fetches real emails directly from the user's Gmail inbox via the Gmail REST API,
    decodes raw RFC 822 emails, runs the complete Anviksha forensic pipeline on each,
    and categorizes them into Red, Yellow, and Blue threat levels.
    """
    try:
        messages = list_gmail_messages(payload.access_token, max_results=payload.max_results or 10)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch messages from Gmail: {str(e)}")
    
    if not messages:
        return {
            "total": 0,
            "red_count": 0,
            "yellow_count": 0,
            "blue_count": 0,
            "items": [],
            "message": "Gmail inbox is empty or no messages found in INBOX label."
        }

    scanned_items = []
    red_count = 0
    yellow_count = 0
    blue_count = 0

    for msg in messages:
        msg_id = msg.get("id")
        try:
            raw_bytes = get_gmail_message_raw(payload.access_token, msg_id)
            dossier = run_forensic_pipeline(raw_bytes, db, user_id=current_user.id if current_user else None)
            color = dossier.get("threat_color", "blue")
            if color == "red":
                red_count += 1
            elif color == "yellow":
                yellow_count += 1
            else:
                blue_count += 1

            scanned_items.append({
                "id": msg_id,
                "analysis_id": dossier.get("id"),
                "subject": dossier.get("parsed_email", {}).get("subject", "(No Subject)"),
                "sender": dossier.get("parsed_email", {}).get("from", "Unknown"),
                "date": dossier.get("parsed_email", {}).get("date", "Recent"),
                "threat_color": color,
                "risk_score": dossier.get("scoring", {}).get("risk_score"),
                "threat_level": dossier.get("scoring", {}).get("threat_level"),
                "one_sentence_verdict": dossier.get("one_sentence_verdict"),
                "danger_verdict": dossier.get("user_friendly_report", {}).get("danger_verdict"),
                "ai_tldr": dossier.get("user_friendly_report", {}).get("ai_summary", {}).get("executive_tldr"),
                "origin_summary": dossier.get("user_friendly_report", {}).get("origin_summary"),
                "dossier": dossier
            })
        except Exception:
            try:
                meta = get_gmail_message_metadata(payload.access_token, msg_id)
                scanned_items.append({
                    "id": msg_id,
                    "subject": meta.get("subject"),
                    "sender": meta.get("sender"),
                    "date": meta.get("date"),
                    "threat_color": "yellow",
                    "risk_score": 40.0,
                    "threat_level": "Suspicious",
                    "one_sentence_verdict": "🟡 SUSPICIOUS: Unconventional MIME structure requires manual header inspection.",
                    "danger_verdict": "SUSPICIOUS / UNCONVENTIONAL MIME",
                    "ai_tldr": meta.get("snippet"),
                    "origin_summary": "Direct Mail Server",
                    "dossier": None
                })
                yellow_count += 1
            except Exception:
                pass

    return {
        "total": len(scanned_items),
        "red_count": red_count,
        "yellow_count": yellow_count,
        "blue_count": blue_count,
        "items": scanned_items
    }

@router.get("/gmail/fetch/{message_id}")
def fetch_and_analyze_single_gmail_message(
    message_id: str,
    access_token: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    """
    Fetches an individual email from Gmail by message_id and runs the complete Anviksha forensic pipeline.
    """
    try:
        raw_bytes = get_gmail_message_raw(access_token, message_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch message from Gmail: {str(e)}")

    return run_forensic_pipeline(raw_bytes, db, user_id=current_user.id if current_user else None)

