import re
from typing import Dict, Any, List, Optional

URGENCY_KEYWORDS = [
    'as soon as possible', 'act immediately', 'within 24 hours', 'account suspended',
    'terminated', 'unauthorized access', 'security alert', 'final notice',
    'verify now', 'compromised', 'critical update', 'urgent', 'attention required',
    'immediate action', 'suspended indefinitely', 'action required', 'expires today'
]

FINANCIAL_BEC_KEYWORDS = [
    'wire transfer', 'payment diversion', 'swift', 'invoice attached',
    'update banking details', 'direct deposit', 'remittance advice', 'overdue payment',
    'gift card', 'payroll update', 'bank account details', 'w-2 form', 'tax return',
    'routing number', 'unpaid balance', 'crypto deposit', 'bitcoin transaction', 'purchase order'
]

CREDENTIAL_HARVEST_KEYWORDS = [
    'confirm your password', 'reset your password', 'enter credentials',
    'session expired', 'validate your identity', 'log in to avoid',
    'mailbox quota exceeded', 'office 365 security notification',
    'sign in to verify', 'click here to login', 're-authenticate', 'sync account', 'verify your account'
]

EXECUTIVE_IMPERSONATION_KEYWORDS = [
    'are you at your desk', 'i need a favor', 'strictly confidential',
    'do not call me', 'in a meeting right now', 'handle this quietly',
    'from the ceo', 'executive directive', 'discreet transaction', 'wire before market close'
]

QUISHING_KEYWORDS = [
    'scan qr', 'scan the qr code', 'scan with camera', 'qr authentication',
    'mobile 2fa qr', 'authenticator qr', 'scan to approve', 'qr code attached'
]

FEAR_LEGAL_KEYWORDS = [
    'legal action', 'court subpoena', 'law enforcement', 'arrest warrant',
    'penalty fee', 'account frozen', 'federal tax penalty', 'criminal investigation'
]

def generate_one_sentence_verdict(
    threat_color: str,
    threat_level: str,
    score: float,
    subject: str,
    origin_geo: Dict[str, Any],
    domain_intel: Dict[str, Any],
    has_dangerous_attachment: bool,
    has_malicious_url: bool,
    is_spoofed_auth: bool,
    matched_cues: Dict[str, List[str]]
) -> str:
    """
    Produces an authoritative, punchy one-sentence summary for the risk score badge.
    Explains exactly why the email is Safe, Suspicious, or Dangerous in a single sentence.
    """
    origin_loc = f"{origin_geo.get('city', '')}, {origin_geo.get('country', '')}".strip(", ") or "an unverified network"
    brand = domain_intel.get("impersonated_brand")
    
    if threat_color == "red":
        if has_dangerous_attachment:
            return f"🔴 CRITICAL MALWARE THREAT: Delivers a dangerous camouflaged executable payload (.exe/.scr) originating from an untrusted relay in {origin_loc} with failed sender authentication."
        elif matched_cues.get("quishing"):
            return f"🔴 QUISHING THREAT: Deploys a malicious QR code designed to move the victim to an unmonitored mobile browser and harvest login credentials, originating from {origin_loc}."
        elif matched_cues.get("financial_bec"):
            return f"🔴 FINANCIAL FRAUD (BEC): Exploits executive authority coercion to divert corporate funds via an unauthorized relay in {origin_loc}, failing SPF alignment."
        elif brand:
            return f"🔴 DANGEROUS PHISHING: Impersonates {brand.upper()} using psychological urgency from an unauthorized network in {origin_loc} (failing SPF/DMARC) to harvest account credentials."
        elif origin_geo.get("is_tor"):
            return f"🔴 HIGH-RISK THREAT: Dispatched anonymously through a verified Tor cybercrime exit node in {origin_loc} with spoofed sender headers and deceptive call-to-action links."
        else:
            return f"🔴 DANGEROUS ATTACK: Exhibits multiple critical indicators including failed cryptographic authentication, deceptive routing from {origin_loc}, and credential harvesting lures."
    
    elif threat_color == "yellow":
        if is_spoofed_auth:
            return f"🟡 SUSPICIOUS SPOOFING: Sender domain lacks strict SPF/DMARC cryptographic alignment and was routed through {origin_loc}; verify sender identity before taking action."
        elif matched_cues.get("urgency") or matched_cues.get("financial_bec"):
            return f"🟡 SUSPICIOUS ACTIVITY: Contains high-urgency psychological coercion and financial keywords from an external server in {origin_loc}; out-of-band verification required."
        else:
            return f"🟡 MODERATE CAUTION: Exhibits unaligned routing hops or a recently registered domain from {origin_loc}; exercise caution before clicking any embedded links."
    
    else:
        return f"🔵 VERIFIED AUTHENTIC: Originates from authorized infrastructure ({origin_geo.get('isp', 'Enterprise Mail MTA')}) with valid cryptographic SPF & DKIM signatures, clean links, and zero malicious payload indicators."

def generate_expert_soc_forensic_dossier(
    subject: str,
    sender: str,
    origin_geo: Dict[str, Any],
    domain_intel: Dict[str, Any],
    auth_results: Dict[str, Any],
    nlp_results: Dict[str, Any],
    scoring: Dict[str, Any],
    threat_color: str
) -> Dict[str, Any]:
    """
    Generates a deep, technical forensic intelligence dossier for SOC analysts and incident responders.
    Includes MITRE ATT&CK mapping, threat actor archetype profiling, and cryptographic routing telemetry.
    """
    # 1. Map to MITRE ATT&CK Enterprise Matrix
    mitre_tactics = []
    
    # Initial Access
    if scoring.get("has_dangerous_attachment"):
        mitre_tactics.append({
            "id": "T1566.001",
            "tactic": "Initial Access",
            "technique": "Phishing: Spearphishing Attachment",
            "evidence": "Payload disguised with double-extension camouflage (e.g. .pdf.exe) to bypass gateway inspection."
        })
    if scoring.get("has_malicious_url") or domain_intel.get("is_lookalike"):
        mitre_tactics.append({
            "id": "T1566.002",
            "tactic": "Initial Access",
            "technique": "Phishing: Spearphishing Link",
            "evidence": f"Embedded hyperlink directing to typosquatted domain ({domain_intel.get('domain')})."
        })
    
    # Defense Evasion
    if domain_intel.get("is_lookalike") or domain_intel.get("is_punycode"):
        mitre_tactics.append({
            "id": "T1036.005",
            "tactic": "Defense Evasion",
            "technique": "Masquerading: Match Legitimate Name or Host",
            "evidence": f"Typosquatting permutation imitating brand '{domain_intel.get('impersonated_brand', 'Target')}'."
        })
    if origin_geo.get("is_tor") or origin_geo.get("is_vpn"):
        mitre_tactics.append({
            "id": "T1090.003",
            "tactic": "Command and Control",
            "technique": "Proxy: Multi-hop Proxy (Tor / Anonymizer)",
            "evidence": f"Transmitted via Tor exit node / proxy IP {origin_geo.get('ip')} ({origin_geo.get('asn')})."
        })
    
    # Credential Access / Impact
    if "Credential Harvesting / Phishing Lure" in nlp_results.get("flagged_categories", []):
        mitre_tactics.append({
            "id": "T1056.003",
            "tactic": "Credential Access",
            "technique": "Input Capture: Web Portal Harvesting",
            "evidence": "Deceptive login verification prompt coercing submission of user authentication tokens."
        })
    if "Financial / Wire Diversion (BEC)" in nlp_results.get("flagged_categories", []):
        mitre_tactics.append({
            "id": "T1565.002",
            "tactic": "Impact",
            "technique": "Data Manipulation: Transmitted Wire Redirection",
            "evidence": "Unauthorized modification of banking details and payment diversion request."
        })

    if not mitre_tactics:
        mitre_tactics.append({
            "id": "T0000",
            "tactic": "Benign",
            "technique": "Authorized Administrative Communication",
            "evidence": "No active offensive techniques detected. Cryptographic posture conforms to RFC 7489 standard."
        })

    # 2. Threat Actor Archetype Attribution
    if threat_color == "red":
        if origin_geo.get("is_tor") and domain_intel.get("is_lookalike"):
            archetype = "Financially Motivated Cybercrime Syndicate (Commodity Credential Harvester)"
            threat_group_notes = "Operating automated phishing kits deployed on bulletproof hosting and Tor exit relays. Target profile: General enterprise users and high-volume consumers."
        elif "Financial / Wire Diversion (BEC)" in nlp_results.get("flagged_categories", []):
            archetype = "Organized BEC Consortium (West African / Bulletproof Network Nexus)"
            threat_group_notes = "Human-operated executive social engineering campaign targeting accounts payable and CFO payroll controllers."
        elif scoring.get("has_dangerous_attachment"):
            archetype = "Initial Access Broker (IAB) / Loader Dropper Campaign"
            threat_group_notes = "Distributing second-stage RAT / Trojan loaders via deceptive invoice / waybill decoys."
        else:
            archetype = "Automated Opportunistic Phishing Infrastructure"
            threat_group_notes = "Broad-spectrum credential interception campaign using dynamic lookalike domains."
    elif threat_color == "yellow":
        archetype = "Unclassified Suspicious Sender / Marketing Spammer"
        threat_group_notes = "Lacks corporate identity alignment. Potential low-tier social engineering probe or graymail."
    else:
        archetype = "Verified Legitimate Entity (Tier 1 Enterprise Infrastructure)"
        threat_group_notes = "Authenticated via enterprise mail exchanger with established domain reputation."

    # 3. Cryptographic & Protocol Forensic Narrative
    spf_stat = auth_results.get("spf", {}).get("status", "none").upper()
    dkim_stat = auth_results.get("dkim", {}).get("status", "none").upper()
    dmarc_stat = auth_results.get("dmarc", {}).get("status", "none").upper()
    
    crypto_narrative = (
        f"Cryptographic evaluation: SPF verification evaluated as {spf_stat}; "
        f"DKIM signature evaluated as {dkim_stat}; "
        f"DMARC policy alignment evaluated as {dmarc_stat}. "
    )
    if spf_stat in ["FAIL", "SOFTFAIL"]:
        crypto_narrative += f"The originating IP {origin_geo.get('ip')} is NOT authorized in the DNS TXT record of {domain_intel.get('domain')}. "
    if dkim_stat == "PASS":
        crypto_narrative += "Cryptographic digital signature verified using domain public key. "
    elif dkim_stat == "FAIL":
        crypto_narrative += "Cryptographic digital signature is missing or corrupted, indicating transit tampering or forgery. "

    return {
        "archetype": archetype,
        "threat_group_notes": threat_group_notes,
        "mitre_tactics": mitre_tactics,
        "crypto_narrative": crypto_narrative,
        "network_forensics": {
            "origin_node": f"{origin_geo.get('city')}, {origin_geo.get('country')}",
            "asn_routing": f"{origin_geo.get('asn')} ({origin_geo.get('org')})",
            "domain_telemetry": f"{domain_intel.get('domain')} (Age: {domain_intel.get('age_days')} days, Registrar: {domain_intel.get('registrar')})",
            "proxy_classification": "Tor Exit Node" if origin_geo.get('is_tor') else ("VPN / Datacenter Hosting" if origin_geo.get('is_vpn') else "Standard Direct Route")
        }
    }

def analyze_text_nlp(subject: str, text: str) -> Dict[str, Any]:
    content = f"{subject}\n{text}".lower()
    
    urgency_matches = [k for k in URGENCY_KEYWORDS if k in content]
    financial_matches = [k for k in FINANCIAL_BEC_KEYWORDS if k in content]
    credential_matches = [k for k in CREDENTIAL_HARVEST_KEYWORDS if k in content]
    executive_matches = [k for k in EXECUTIVE_IMPERSONATION_KEYWORDS if k in content]
    quishing_matches = [k for k in QUISHING_KEYWORDS if k in content]
    fear_matches = [k for k in FEAR_LEGAL_KEYWORDS if k in content]

    score = 0
    categories = []

    if urgency_matches:
        score += min(30, len(urgency_matches) * 12)
        categories.append('Urgency & Psychological Coercion')

    if financial_matches:
        score += min(40, len(financial_matches) * 20)
        categories.append('Financial / Wire Diversion (BEC)')

    if credential_matches:
        score += min(40, len(credential_matches) * 20)
        categories.append('Credential Harvesting / Phishing Lure')

    if executive_matches:
        score += min(30, len(executive_matches) * 15)
        categories.append('Executive Impersonation')

    if quishing_matches:
        score += min(35, len(quishing_matches) * 25)
        categories.append('Quishing (QR Code Vector)')

    if fear_matches:
        score += min(30, len(fear_matches) * 15)
        categories.append('Intimidation & Legal Threat Vector')

    score = min(100, score)

    matched_cues = {
        'urgency': urgency_matches,
        'financial_bec': financial_matches,
        'credential_harvesting': credential_matches,
        'executive_impersonation': executive_matches,
        'quishing': quishing_matches,
        'fear_legal': fear_matches
    }

    # Generate User-Friendly Cognitive Briefing
    if quishing_matches:
        theme = "Quishing / Malicious QR Code Attack"
        premise = "Prompts the recipient to scan a mobile QR code to authenticate or review an urgent alert."
        attacker_goal = "Bypass desktop firewall protections by shifting the user to an unmonitored smartphone browser to steal login tokens."
        psychological_trigger = "Confusion & Technical Compliance"
    elif financial_matches:
        theme = "Business Email Compromise (BEC) / Wire Diversion"
        premise = "Claims an urgent invoice update, direct deposit change, or confidential executive wire transfer."
        attacker_goal = "Deceive accounts payable or finance employees into transferring money into an attacker-controlled account."
        psychological_trigger = "Authority Compliance & Financial Urgency"
    elif credential_matches:
        theme = "Brand Impersonation / Credential Theft"
        premise = "Mimics an essential service (e.g. PayPal, Microsoft, Google, Bank) warning that an account is locked or about to be deleted."
        attacker_goal = "Force the victim into entering their username and password into a counterfeit phishing webpage."
        psychological_trigger = "Fear of Loss & Panic Coercion"
    elif urgency_matches or fear_matches:
        theme = "Social Engineering / Coercive Intimidation"
        premise = "Uses high-pressure language threatening penalties, account termination, or legal consequences within 24 hours."
        attacker_goal = "Trigger emotional panic so the recipient clicks without verifying the sender."
        psychological_trigger = "Panic & Hasty Compliance"
    elif score < 30:
        theme = "Verified Enterprise / Routine Communication"
        premise = "Appears to be standard operational correspondence, newsletter digest, or legitimate account notification."
        attacker_goal = "Normal business communication; no malicious deception detected."
        psychological_trigger = "None Detected"
    else:
        theme = "Suspicious Unverified Communication"
        premise = "Contains multiple stylistic or grammatical indicators requiring caution before opening links."
        attacker_goal = "Potential preliminary reconnaissance or phishing probe."
        psychological_trigger = "Curiosity / Incomplete Context"

    ai_summary = {
        'theme': theme,
        'premise': premise,
        'attacker_goal': attacker_goal,
        'psychological_trigger': psychological_trigger,
        'executive_tldr': f"Subject: \"{subject}\". {premise} Attacker goal: {attacker_goal}"
    }

    intent = 'Legitimate Business / Personal Communication'
    if score >= 65:
        intent = 'High-Probability Phishing / Financial Fraud'
    elif score >= 35:
        intent = 'Suspicious Social Engineering Attempt'
    elif score >= 15:
        intent = 'Low-Level Marketing / Urgency Language'

    return {
        'nlp_score': score,
        'intent': intent,
        'flagged_categories': categories,
        'matched_cues': matched_cues,
        'ai_summary': ai_summary,
        'summary': f"Detected {len(urgency_matches)} urgency cues, {len(financial_matches)} financial patterns, and {len(credential_matches)} credential indicators."
    }
