import re
from datetime import datetime
from email.utils import parsedate_to_datetime
import ipaddress
from typing import List, Dict, Any, Optional

IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local)
    except Exception:
        return False

def parse_received_hops(received_headers: List[str]) -> List[Dict[str, Any]]:
    hops = []
    # Received headers in raw emails are prepended in reverse chronological order
    # (Topmost is the final receiving MTA, bottommost is originating MTA)
    for idx, header in enumerate(reversed(received_headers)):
        hop_num = idx + 1
        header_clean = " ".join(header.split())
        
        # Extract IPs
        ips = IP_REGEX.findall(header_clean)
        public_ips = [ip for ip in ips if is_public_ip(ip)]
        primary_ip = public_ips[0] if public_ips else (ips[0] if ips else None)

        # Extract 'from' host
        from_match = re.search(r'from\s+([^\s;]+)', header_clean, re.IGNORECASE)
        from_host = from_match.group(1) if from_match else "unknown"

        # Extract 'by' host
        by_match = re.search(r'by\s+([^\s;]+)', header_clean, re.IGNORECASE)
        by_host = by_match.group(1) if by_match else "unknown"

        # Extract timestamp after ';'
        timestamp_str = None
        parsed_dt = None
        if ';' in header_clean:
            timestamp_str = header_clean.split(';')[-1].strip()
            try:
                parsed_dt = parsedate_to_datetime(timestamp_str)
            except Exception:
                parsed_dt = None

        hops.append({
            'hop': hop_num,
            'from_host': from_host,
            'by_host': by_host,
            'ip': primary_ip,
            'is_public': is_public_ip(primary_ip) if primary_ip else False,
            'timestamp': timestamp_str,
            'datetime': parsed_dt.isoformat() if parsed_dt else None,
            'raw': header_clean
        })

    # Calculate delays between hops
    for i in range(1, len(hops)):
        prev_dt = hops[i-1].get('datetime')
        curr_dt = hops[i].get('datetime')
        if prev_dt and curr_dt:
            try:
                d1 = datetime.fromisoformat(prev_dt)
                d2 = datetime.fromisoformat(curr_dt)
                delay_sec = max(0, int((d2 - d1).total_seconds()))
                hops[i]['delay_seconds'] = delay_sec
            except Exception:
                hops[i]['delay_seconds'] = 0
        else:
            hops[i]['delay_seconds'] = 0

    return hops

def extract_sender_domain(email_str: str) -> str:
    match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_str)
    return match.group(1).lower() if match else ""

def detect_header_anomalies(parsed_email: Dict[str, Any], hops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    anomalies = []
    
    sender = parsed_email.get('from', '')
    return_path = parsed_email.get('return_path', '')
    reply_to = parsed_email.get('reply_to', '')
    message_id = parsed_email.get('message_id', '')

    sender_domain = extract_sender_domain(sender)
    return_domain = extract_sender_domain(return_path) if return_path else ""
    reply_domain = extract_sender_domain(reply_to) if reply_to else ""

    # 1. Return-Path Mismatch
    if return_domain and sender_domain and return_domain != sender_domain:
        anomalies.append({
            'type': 'RETURN_PATH_MISMATCH',
            'severity': 'HIGH',
            'title': 'Return-Path Domain Mismatch',
            'description': f'From domain ({sender_domain}) does not match Return-Path domain ({return_domain}). Common indicator of spoofing/bounce redirection.'
        })

    # 2. Reply-To Mismatch
    if reply_domain and sender_domain and reply_domain != sender_domain:
        anomalies.append({
            'type': 'REPLY_TO_MISMATCH',
            'severity': 'HIGH',
            'title': 'Reply-To Address Divergence',
            'description': f'Replies will go to {reply_to} instead of sender domain {sender_domain}. Standard phishing trap.'
        })

    # 3. Display Name Spoofing Check
    # E.g., "CEO Name <hacker@gmail.com>" or "PayPal Security <noreply-service-alert@evil-domain.com>"
    if '<' in sender and '>' in sender:
        display_part = sender.split('<')[0].strip(' "\'')
        addr_part = sender.split('<')[1].split('>')[0].strip()
        # Look for corporate brand names in display name when domain is generic or suspicious
        trusted_brands = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'bank', 'support', 'security', 'netflix', 'dhl', 'fedex']
        for brand in trusted_brands:
            if brand in display_part.lower() and brand not in sender_domain:
                anomalies.append({
                    'type': 'DISPLAY_NAME_SPOOFING',
                    'severity': 'CRITICAL',
                    'title': f'Deceptive Display Name ({brand.upper()})',
                    'description': f'Display name mimics "{display_part}" but actual address domain is "{sender_domain}".'
                })
                break

    # 4. Message-ID Domain Validation
    if message_id:
        msg_id_domain = extract_sender_domain(message_id)
        if msg_id_domain and sender_domain and msg_id_domain != sender_domain:
            anomalies.append({
                'type': 'MESSAGE_ID_ANOMALY',
                'severity': 'MEDIUM',
                'title': 'Message-ID Domain Discrepancy',
                'description': f'Message-ID claims origin domain {msg_id_domain}, differing from From domain {sender_domain}.'
            })
    else:
        anomalies.append({
            'type': 'MISSING_MESSAGE_ID',
            'severity': 'MEDIUM',
            'title': 'Missing RFC 5322 Message-ID',
            'description': 'Email lacks a required Message-ID header, characteristic of automated mass spam engines.'
        })

    # 5. Routing Hop Anomalies
    if not hops:
        anomalies.append({
            'type': 'NO_RECEIVED_HEADERS',
            'severity': 'HIGH',
            'title': 'Zero Relay Headers Found',
            'description': 'Email has no Received headers; forensic transmission path cannot be authenticated.'
        })

    return anomalies
