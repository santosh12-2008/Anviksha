import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.community import CommunityAttackReport, DomainThreatReport
from pydantic import BaseModel

router = APIRouter(prefix="/community", tags=["Community Threat Defense"])

class CommunityReportCreate(BaseModel):
    author_name: Optional[str] = "Anonymous Defender"
    target_industry: Optional[str] = "General"
    email_subject: str
    sender_domain: Optional[str] = None
    threat_category: str
    story: str
    financial_loss: Optional[str] = "$0 (Prevented)"
    warning_signs: Optional[List[str]] = []
    prevention_advice: Optional[str] = None

class DomainReportCreate(BaseModel):
    domain_or_email: str
    threat_type: str
    description: str
    evidence_snippet: Optional[str] = None
    reported_by: Optional[str] = "Guest Community User"

@router.get("")
def get_community_reports(
    threat_category: Optional[str] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(CommunityAttackReport)
    if threat_category and threat_category != 'all':
        query = query.filter(CommunityAttackReport.threat_category.ilike(f"%{threat_category}%"))
    if q:
        query = query.filter(
            (CommunityAttackReport.email_subject.ilike(f"%{q}%")) |
            (CommunityAttackReport.story.ilike(f"%{q}%")) |
            (CommunityAttackReport.sender_domain.ilike(f"%{q}%"))
        )
    reports = query.order_by(CommunityAttackReport.created_at.desc()).all()
    
    results = []
    for r in reports:
        signs = []
        if r.warning_signs:
            try:
                signs = json.loads(r.warning_signs) if isinstance(r.warning_signs, str) else r.warning_signs
            except:
                signs = [r.warning_signs]
        results.append({
            "id": r.id,
            "author_name": r.author_name,
            "target_industry": r.target_industry,
            "email_subject": r.email_subject,
            "sender_domain": r.sender_domain,
            "threat_category": r.threat_category,
            "story": r.story,
            "financial_loss": r.financial_loss,
            "warning_signs": signs,
            "prevention_advice": r.prevention_advice,
            "likes_count": r.likes_count,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else "Recent"
        })
    return results

@router.post("")
def submit_community_report(
    payload: CommunityReportCreate,
    db: Session = Depends(get_db)
):
    report = CommunityAttackReport(
        author_name=payload.author_name or "Anonymous Defender",
        target_industry=payload.target_industry or "General",
        email_subject=payload.email_subject,
        sender_domain=payload.sender_domain,
        threat_category=payload.threat_category,
        story=payload.story,
        financial_loss=payload.financial_loss or "$0 (Prevented)",
        warning_signs=json.dumps(payload.warning_signs or []),
        prevention_advice=payload.prevention_advice,
        likes_count=1
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return {"message": "Attack experience shared successfully to help protect others!", "id": report.id}

@router.post("/{report_id}/like")
def like_community_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(CommunityAttackReport).filter(CommunityAttackReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    report.likes_count += 1
    db.commit()
    return {"id": report.id, "likes_count": report.likes_count}

@router.get("/match")
def match_similar_experiences(
    subject: Optional[str] = "",
    domain: Optional[str] = "",
    category: Optional[str] = "",
    db: Session = Depends(get_db)
):
    """
    Searches the community database for victim stories with matching domain, brand, or subject keywords.
    """
    query = db.query(CommunityAttackReport)
    matches = []

    if domain:
        domain_matches = query.filter(CommunityAttackReport.sender_domain.ilike(f"%{domain}%")).all()
        for m in domain_matches:
            if m not in matches:
                matches.append(m)

    # Search for keywords in subject (e.g. paypal, wire, invoice, dhl, suspension)
    keywords = [w.lower() for w in subject.split() if len(w) > 3]
    for kw in keywords[:4]:
        kw_matches = query.filter(
            (CommunityAttackReport.email_subject.ilike(f"%{kw}%")) |
            (CommunityAttackReport.story.ilike(f"%{kw}%"))
        ).limit(3).all()
        for m in kw_matches:
            if m not in matches:
                matches.append(m)

    if not matches and category:
        category_matches = query.filter(CommunityAttackReport.threat_category.ilike(f"%{category}%")).limit(2).all()
        for m in category_matches:
            if m not in matches:
                matches.append(m)

    # Limit to top 3 relevant cases
    top_matches = matches[:3]
    results = []
    for r in top_matches:
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

@router.post("/report-domain")
def report_domain_threat(payload: DomainReportCreate, db: Session = Depends(get_db)):
    report = DomainThreatReport(
        domain_or_email=payload.domain_or_email,
        threat_type=payload.threat_type,
        description=payload.description,
        evidence_snippet=payload.evidence_snippet,
        reported_by=payload.reported_by,
        status="Under Review"
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return {
        "message": f"Domain '{payload.domain_or_email}' successfully recorded in threat intelligence queue for forensic investigation.",
        "id": report.id
    }

@router.get("/reported-domains")
def get_reported_domains(db: Session = Depends(get_db)):
    records = db.query(DomainThreatReport).order_by(DomainThreatReport.created_at.desc()).limit(50).all()
    return [{
        "id": r.id,
        "domain_or_email": r.domain_or_email,
        "threat_type": r.threat_type,
        "description": r.description,
        "reported_by": r.reported_by,
        "status": r.status,
        "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else "Recent"
    } for r in records]
