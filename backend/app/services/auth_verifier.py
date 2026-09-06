import re
from typing import Dict, Any, Optional
try:
    import dns.resolver
except ImportError:
    dns = None

def get_dns_txt_records(domain: str) -> list:
    if not dns or not domain:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        answers = resolver.resolve(domain, 'TXT')
        records = []
        for rdata in answers:
            txt_str = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings])
            records.append(txt_str)
        return records
    except Exception:
        return []

def verify_spf(domain: str, sender_ip: Optional[str], raw_auth_results: Optional[str] = None) -> Dict[str, Any]:
    # Check if upstream MTA already authenticated SPF
    if raw_auth_results:
        spf_match = re.search(r'spf=(\w+)', raw_auth_results, re.IGNORECASE)
        if spf_match:
            status = spf_match.group(1).lower()
            return {
                'status': status,
                'record': 'Extracted from Authentication-Results MTA header',
                'details': f'MTA reported SPF {status.upper()} for sender IP {sender_ip or "unknown"}.'
            }

    # Query live DNS for SPF record
    records = get_dns_txt_records(domain)
    spf_record = next((r for r in records if r.startswith('v=spf1')), None)

    if not spf_record:
        return {
            'status': 'none',
            'record': None,
            'details': f'No SPF record published for domain {domain}. Vulnerable to direct sender forgery.'
        }

    # Basic evaluation of SPF record
    if sender_ip and sender_ip in spf_record:
        return {
            'status': 'pass',
            'record': spf_record,
            'details': f'Originating IP {sender_ip} explicitly authorized in SPF record.'
        }
    
    if '-all' in spf_record:
        return {
            'status': 'fail',
            'record': spf_record,
            'details': f'Hard fail (-all): IP {sender_ip or "unknown"} is not listed in SPF policy.'
        }
    elif '~all' in spf_record:
        return {
            'status': 'softfail',
            'record': spf_record,
            'details': f'Soft fail (~all): IP {sender_ip or "unknown"} is questionable under SPF policy.'
        }
    else:
        return {
            'status': 'neutral',
            'record': spf_record,
            'details': f'SPF policy is neutral or permissive (?all): {spf_record}'
        }

def verify_dkim(headers: Dict[str, Any], raw_auth_results: Optional[str] = None) -> Dict[str, Any]:
    # Check Authentication-Results header
    if raw_auth_results:
        dkim_match = re.search(r'dkim=(\w+)', raw_auth_results, re.IGNORECASE)
        if dkim_match:
            status = dkim_match.group(1).lower()
            return {
                'status': status,
                'has_signature': True,
                'details': f'Upstream MTA reported DKIM {status.upper()}'
            }

    dkim_sig = headers.get('DKIM-Signature') or headers.get('dkim-signature')
    if not dkim_sig:
        return {
            'status': 'none',
            'has_signature': False,
            'details': 'No DKIM cryptographic signature present in headers.'
        }

    sig_str = dkim_sig[0] if isinstance(dkim_sig, list) else str(dkim_sig)
    # Parse d= and s=
    domain_match = re.search(r'd=([a-zA-Z0-9.-]+)', sig_str)
    selector_match = re.search(r's=([a-zA-Z0-9.-]+)', sig_str)
    d = domain_match.group(1) if domain_match else 'unknown'
    s = selector_match.group(1) if selector_match else 'unknown'

    return {
        'status': 'pass',
        'has_signature': True,
        'signing_domain': d,
        'selector': s,
        'details': f'DKIM signature detected for domain "{d}" using selector "{s}".'
    }

def verify_dmarc(domain: str, spf_result: str, dkim_result: str) -> Dict[str, Any]:
    dmarc_domain = f"_dmarc.{domain}"
    records = get_dns_txt_records(dmarc_domain)
    dmarc_record = next((r for r in records if r.startswith('v=DMARC1')), None)

    if not dmarc_record:
        return {
            'status': 'none',
            'policy': 'none',
            'record': None,
            'aligned': False,
            'details': f'No DMARC policy published for {domain}. Mailbox providers cannot enforce spoofing rejection.'
        }

    policy_match = re.search(r'p=(\w+)', dmarc_record, re.IGNORECASE)
    policy = policy_match.group(1).lower() if policy_match else 'none'

    # DMARC passes if either SPF or DKIM passes with alignment
    aligned = (spf_result == 'pass') or (dkim_result == 'pass')
    status = 'pass' if aligned else 'fail'

    return {
        'status': status,
        'policy': policy,
        'record': dmarc_record,
        'aligned': aligned,
        'details': f'DMARC {status.upper()} (Policy: {policy.upper()}). SPF={spf_result}, DKIM={dkim_result}.'
    }

def verify_protocols(domain: str, sender_ip: Optional[str], headers: Dict[str, Any]) -> Dict[str, Any]:
    auth_results_header = headers.get('Authentication-Results') or headers.get('authentication-results')
    raw_auth = auth_results_header[0] if isinstance(auth_results_header, list) else (str(auth_results_header) if auth_results_header else None)

    spf = verify_spf(domain, sender_ip, raw_auth)
    dkim = verify_dkim(headers, raw_auth)
    dmarc = verify_dmarc(domain, spf['status'], dkim['status'])

    # Determine overall protocol health
    passed_count = sum([1 for x in [spf['status'], dkim['status'], dmarc['status']] if x == 'pass'])
    failed_count = sum([1 for x in [spf['status'], dkim['status'], dmarc['status']] if x in ['fail', 'softfail']])

    if failed_count > 0:
        verdict = 'CRITICAL_FAILURE' if failed_count >= 2 else 'PARTIAL_FAILURE'
    elif passed_count == 3:
        verdict = 'FULLY_AUTHENTICATED'
    elif passed_count >= 1:
        verdict = 'PARTIALLY_AUTHENTICATED'
    else:
        verdict = 'UNAUTHENTICATED'

    return {
        'verdict': verdict,
        'spf': spf,
        'dkim': dkim,
        'dmarc': dmarc,
        'auth_results_raw': raw_auth
    }
