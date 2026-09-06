import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.models.analysis import EmailAnalysis
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/forensics", tags=["Forensic Dossiers & Reports"])

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Digital Forensic Evidence Dossier - Case #{{case_id}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 40px; margin: 0; }
        .card { background: #131b2e; border: 1px solid #23304d; border-radius: 8px; padding: 24px; margin-bottom: 24px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #3b82f6; padding-bottom: 16px; margin-bottom: 24px; }
        .badge { padding: 6px 12px; border-radius: 4px; font-weight: bold; text-transform: uppercase; font-size: 12px; }
        .badge-red { background: #7f1d1d; color: #fecaca; border: 1px solid #ef4444; }
        .badge-green { background: #064e3b; color: #a7f3d0; border: 1px solid #10b981; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #1e293b; font-size: 13px; }
        th { color: #94a3b8; background: #0f172a; }
        .score { font-size: 36px; font-weight: 800; color: {{score_color}}; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin:0; font-size:24px; color:#60a5fa;">DIGITAL FORENSIC EVIDENCE REPORT</h1>
            <p style="margin:4px 0 0; color:#94a3b8;">Case File ID: {{case_id}} | Chain-of-Custody Verified</p>
        </div>
        <div>
            <span class="badge {{badge_class}}">{{threat_level}}</span>
        </div>
    </div>

    <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
        <div>
            <h3 style="margin:0 0 8px;">Unified Threat Risk Score</h3>
            <div class="score">{{risk_score}} / 100</div>
            <p style="margin:8px 0 0; color:#94a3b8; font-size:14px;">{{recommendation}}</p>
        </div>
        <div style="text-align:right; font-size:13px; color:#cbd5e1;">
            <p><strong>Investigating Analyst:</strong> {{analyst_name}}</p>
            <p><strong>Analysis Timestamp:</strong> {{timestamp}}</p>
            <p><strong>Origin IP:</strong> {{origin_ip}} ({{origin_city}}, {{origin_country}})</p>
        </div>
    </div>

    <div class="card">
        <h3 style="margin-top:0;">Email Header Forensics</h3>
        <table>
            <tr><th>Field</th><th>Extracted Value</th></tr>
            <tr><td>Subject</td><td>{{subject}}</td></tr>
            <tr><td>Sender (From)</td><td>{{sender}}</td></tr>
            <tr><td>Return-Path</td><td>{{return_path}}</td></tr>
            <tr><td>Reply-To</td><td>{{reply_to}}</td></tr>
            <tr><td>Recipient</td><td>{{recipient}}</td></tr>
            <tr><td>Message-ID</td><td>{{message_id}}</td></tr>
        </table>
    </div>

    <div class="card">
        <h3 style="margin-top:0;">Sender Authentication Breakdown</h3>
        <table>
            <tr><th>Protocol</th><th>Status</th><th>Validation Details</th></tr>
            <tr><td>SPF</td><td><strong>{{spf}}</strong></td><td>{{spf_detail}}</td></tr>
            <tr><td>DKIM</td><td><strong>{{dkim}}</strong></td><td>{{dkim_detail}}</td></tr>
            <tr><td>DMARC</td><td><strong>{{dmarc}}</strong></td><td>{{dmarc_detail}}</td></tr>
        </table>
    </div>

    <div class="card">
        <h3 style="margin-top:0;">Origin Traceability & Transmission Relay Path</h3>
        <table>
            <tr><th>Hop</th><th>Sending Server</th><th>Receiving Server</th><th>IP Address</th><th>Transit Latency</th></tr>
            {{hops_rows}}
        </table>
    </div>
</body>
</html>
"""

@router.get("/{analysis_id}/report")
def export_forensic_report(
    analysis_id: int,
    format: str = "json",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    record = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Forensic record not found")

    dossier = json.loads(record.forensic_data)

    audit_trail = {
        "case_id": f"CASE-EML-{record.id:06d}",
        "analyst_id": current_user.id,
        "analyst_name": current_user.full_name or current_user.username,
        "classification": record.threat_level,
        "risk_index": record.risk_score,
        "export_timestamp": datetime.now(timezone.utc).isoformat(),
        "origin_coordinates": {
            "country": record.origin_country,
            "city": record.origin_city,
            "ip": record.origin_ip,
            "isp": record.origin_isp
        },
        "digital_forensics_summary": {
            "spf": record.spf_status,
            "dkim": record.dkim_status,
            "dmarc": record.dmarc_status,
            "total_hops": len(dossier.get("hops", [])),
            "flagged_urls": len([u for u in dossier.get("urls", []) if u.get("is_malicious")]),
            "flagged_attachments": len([a for a in dossier.get("attachments", []) if a.get("is_dangerous_extension")])
        },
        "technical_evidence": dossier
    }

    audit = AuditLog(
        user_id=current_user.id,
        action="EXPORT_FORENSIC_REPORT",
        resource_type="REPORT",
        resource_id=str(record.id),
        details=f"Exported legal forensic dossier for analysis #{record.id} in {format.upper()} format"
    )
    db.add(audit)
    db.commit()

    if format == "json":
        return audit_trail

    hops_rows = "".join([f"<tr><td>Hop #{h.get('hop')}</td><td>{h.get('from_host')}</td><td>{h.get('by_host')}</td><td>{h.get('ip')}</td><td>{h.get('delay_seconds', 0)}s</td></tr>" for h in dossier.get("hops", [])])

    replacements = {
        "{{case_id}}": f"CASE-EML-{record.id:06d}",
        "{{badge_class}}": "badge-red" if record.risk_score > 50 else "badge-green",
        "{{threat_level}}": record.threat_level,
        "{{risk_score}}": str(record.risk_score),
        "{{score_color}}": "#ef4444" if record.risk_score > 50 else "#10b981",
        "{{recommendation}}": dossier.get("scoring", {}).get("recommendation", ""),
        "{{analyst_name}}": current_user.full_name or current_user.username,
        "{{timestamp}}": record.created_at.isoformat() if record.created_at else "N/A",
        "{{origin_ip}}": record.origin_ip or "Unresolved",
        "{{origin_city}}": record.origin_city or "Unknown",
        "{{origin_country}}": record.origin_country or "Unknown",
        "{{subject}}": record.subject or "",
        "{{sender}}": record.sender or "",
        "{{return_path}}": record.return_path or "None",
        "{{reply_to}}": record.reply_to or "None",
        "{{recipient}}": record.recipient or "",
        "{{message_id}}": record.message_id or "Missing",
        "{{spf}}": record.spf_status.upper(),
        "{{spf_detail}}": dossier.get("authentication", {}).get("spf", {}).get("details", ""),
        "{{dkim}}": record.dkim_status.upper(),
        "{{dkim_detail}}": dossier.get("authentication", {}).get("dkim", {}).get("details", ""),
        "{{dmarc}}": record.dmarc_status.upper(),
        "{{dmarc_detail}}": dossier.get("authentication", {}).get("dmarc", {}).get("details", ""),
        "{{hops_rows}}": hops_rows
    }

    html = HTML_TEMPLATE
    for key, val in replacements.items():
        html = html.replace(key, str(val))

    return Response(content=html, media_type="text/html")
