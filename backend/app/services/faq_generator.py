from typing import List, Dict, Any

def generate_predictive_faqs(
    threat_level: str,
    threat_color: str,
    has_malicious_urls: bool,
    has_dangerous_attachments: bool,
    is_spoofed_auth: bool,
    origin_country: str,
    impersonated_brand: str = None
) -> List[Dict[str, str]]:
    """
    Generates tailored, predictive questions and answers that users are most likely to ask
    based on the specific threats detected in this email.
    """
    faqs = []

    # 1. URL threat question
    if has_malicious_urls:
        faqs.append({
            "question": "What if I already clicked the link in this email?",
            "answer": "If you clicked the link, disconnect from your network immediately. If you entered your username or password on that page, go to the official website directly (NOT using the link in the email) from another browser or device and change your password right away. If you use the same password elsewhere, update those accounts too and enable Two-Factor Authentication (2FA)."
        })

    # 2. Attachment threat question
    if has_dangerous_attachments:
        faqs.append({
            "question": "Could my computer be infected if I opened or downloaded the attachment?",
            "answer": "Yes. The attachment contains executable, macro-enabled, or deceptive double-extension code designed to deploy malware or steal local files. Run a full antivirus/antimalware scan immediately. Do not open or enable macros in the file. If you are on a corporate network, notify your IT or Security Helpdesk immediately so they can isolate the machine."
        })
    else:
        faqs.append({
            "question": "Can my device get hacked just by opening or reading an email?",
            "answer": "Generally, simply opening and viewing the text of an email in modern email clients (like Gmail or Outlook) will not infect your computer. Attackers rely on getting you to click malicious links, download attachments, or scan QR codes. However, viewing remote images can confirm to the attacker that your email address is active."
        })

    # 3. Spoofing / Authentication question
    if is_spoofed_auth:
        target_name = impersonated_brand or "the apparent sender"
        faqs.append({
            "question": f"How was the sender able to display {target_name} when it didn't come from them?",
            "answer": "Email protocols (SMTP) were originally created without built-in identity verification. Just like writing a fake return address on a paper envelope, attackers can type whatever they want in the 'From' field. Modern defenses like SPF, DKIM, and DMARC were created to stop this — Anviksha caught this email specifically because its cryptographic SPF/DKIM authentication checks failed."
        })

    # 4. Geolocation / Foreign Origin question
    if origin_country and origin_country not in ['Unknown', 'Local Network']:
        faqs.append({
            "question": f"Why does the trace show the email originated from {origin_country}?",
            "answer": f"By analyzing the earliest 'Received' mail server header, Anviksha extracted the original transmitting IP address. This IP resolves to {origin_country}. Attackers frequently route attacks through compromised servers, bulletproof hosting, or anonymization proxies (such as Tor or commercial VPNs) located in foreign jurisdictions to hide their true identity."
        })

    # 5. Remediation question
    faqs.append({
        "question": "How can I block this attacker from emailing me again?",
        "answer": "Use your email provider's 'Report Phishing' or 'Block Sender' button. If this is a corporate email, forward it to your organization's security team (e.g., phish@company.com). Anviksha also allows you to submit this domain to our community database so other organizations and threat intelligence feeds are alerted."
    })

    # 6. For benign emails
    if threat_color == 'blue':
        faqs = [
            {
                "question": "Why is this email marked as verified safe?",
                "answer": "This email passed cryptographic SPF and DKIM signatures, was routed through authorized infrastructure matching the sender's legitimate domain, contains no known malicious links or payloads, and exhibits no social engineering manipulation patterns."
            },
            {
                "question": "Could a safe email still be tricky?",
                "answer": "Even when an email comes from authorized infrastructure, always exercise standard caution if an email unexpectedly asks for sensitive information or money. When in doubt, verify through an out-of-band channel like a phone call."
            }
        ]

    return faqs
