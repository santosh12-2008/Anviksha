from typing import Dict, Any, List

def calculate_unified_risk_score(
    header_anomalies: List[Dict[str, Any]],
    auth_results: Dict[str, Any],
    geo_data: Dict[str, Any],
    url_analysis: List[Dict[str, Any]],
    attachment_analysis: List[Dict[str, Any]],
    nlp_results: Dict[str, Any]
) -> Dict[str, Any]:
    score = 0.0
    breakdown = []

    # 1. Header & Routing Anomalies (Max 25 pts)
    anomaly_score = 0.0
    for anom in header_anomalies:
        sev = anom.get('severity', 'LOW')
        if sev == 'CRITICAL':
            anomaly_score += 20.0
        elif sev == 'HIGH':
            anomaly_score += 12.0
        elif sev == 'MEDIUM':
            anomaly_score += 6.0
    anomaly_score = min(25.0, anomaly_score)
    if anomaly_score > 0:
        score += anomaly_score
        breakdown.append({
            'factor': 'Header & Routing Anomalies',
            'points': round(anomaly_score, 1),
            'max': 25,
            'detail': str(len(header_anomalies)) + ' structural header inconsistencies flagged.'
        })

    # 2. SPF / DKIM / DMARC Authentication (Max 25 pts)
    auth_score = 0.0
    spf_status = auth_results.get('spf', {}).get('status', 'none')
    dkim_status = auth_results.get('dkim', {}).get('status', 'none')
    dmarc_status = auth_results.get('dmarc', {}).get('status', 'none')

    if spf_status in ['fail', 'softfail']:
        auth_score += 10.0
    elif spf_status == 'none':
        auth_score += 5.0

    if dkim_status in ['fail', 'none']:
        auth_score += 8.0

    if dmarc_status in ['fail', 'none']:
        auth_score += 7.0

    auth_score = min(25.0, auth_score)
    if auth_score > 0:
        score += auth_score
        breakdown.append({
            'factor': 'Protocol Authentication Failures (SPF/DKIM/DMARC)',
            'points': round(auth_score, 1),
            'max': 25,
            'detail': 'SPF: ' + str(spf_status).upper() + ', DKIM: ' + str(dkim_status).upper() + ', DMARC: ' + str(dmarc_status).upper()
        })

    # 3. Origin IP Intelligence & Geolocation (Max 20 pts)
    ip_score = 0.0
    if geo_data.get('is_tor'):
        ip_score += 20.0
    elif geo_data.get('is_vpn'):
        ip_score += 12.0
    
    abuse_score = geo_data.get('abuse_score', 0)
    if abuse_score > 70:
        ip_score += 10.0
    elif abuse_score > 30:
        ip_score += 5.0

    ip_score = min(20.0, ip_score)
    if ip_score > 0:
        score += ip_score
        city_str = str(geo_data.get('city', 'Unknown'))
        country_str = str(geo_data.get('country', 'Unknown'))
        breakdown.append({
            'factor': 'Origin IP Threat & Anonymization',
            'points': round(ip_score, 1),
            'max': 20,
            'detail': 'Origin: ' + city_str + ', ' + country_str + ' (Abuse score: ' + str(abuse_score) + '%).'
        })

    # 4. Content NLP & Social Engineering (Max 20 pts)
    nlp_raw = nlp_results.get('nlp_score', 0)
    nlp_weighted = min(20.0, (nlp_raw / 100.0) * 20.0)
    if nlp_weighted > 0:
        score += nlp_weighted
        breakdown.append({
            'factor': 'Social Engineering & BEC NLP Analysis',
            'points': round(nlp_weighted, 1),
            'max': 20,
            'detail': nlp_results.get('intent', 'Urgency detected')
        })

    # 5. IOC Threat Feeds (URLs & Attachments) (Max 20 pts)
    ioc_score = 0.0
    malicious_urls = [u for u in url_analysis if u.get('is_malicious')]
    if malicious_urls:
        ioc_score += min(15.0, len(malicious_urls) * 10.0)

    dangerous_attachments = [a for a in attachment_analysis if a.get('is_dangerous_extension')]
    if dangerous_attachments:
        ioc_score += 15.0

    ioc_score = min(20.0, ioc_score)
    if ioc_score > 0:
        score += ioc_score
        breakdown.append({
            'factor': 'Malicious URLs & Attachment IOCs',
            'points': round(ioc_score, 1),
            'max': 20,
            'detail': str(len(malicious_urls)) + ' high-risk URLs and ' + str(len(dangerous_attachments)) + ' dangerous attachments found.'
        })

    final_score = min(100.0, round(score, 1))

    if final_score >= 75.0:
        threat_level = 'Malicious Phishing / Fraud'
        badge_color = 'red'
        recommendation = 'QUARANTINE IMMEDIATELY: Block sender domain, reset recipient session credentials, and isolate origin IP.'
    elif final_score >= 50.0:
        threat_level = 'Suspicious'
        badge_color = 'amber'
        recommendation = 'DEFENSIVE SCRUTINY: Display warning banner to user, verify sender via secondary channel, sandbox links.'
    elif final_score >= 25.0:
        threat_level = 'Low Risk'
        badge_color = 'yellow'
        recommendation = 'MONITOR: Email shows minor discrepancies (e.g. newsletter marketing or third-party relay).'
    else:
        threat_level = 'Safe'
        badge_color = 'green'
        recommendation = 'DELIVER NORMALLY: All protocol authentications valid, trustworthy origin, and no phishing cues detected.'

    return {
        'risk_score': final_score,
        'threat_level': threat_level,
        'badge_color': badge_color,
        'recommendation': recommendation,
        'breakdown': breakdown
    }
