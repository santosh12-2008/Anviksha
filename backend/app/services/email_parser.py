import email
from email import policy
from email.parser import BytesParser
import io
import re
import hashlib
from typing import Dict, Any, List

try:
    import extract_msg
except ImportError:
    extract_msg = None

URL_PATTERN = re.compile(r'https?://[^\s<>"]+')

def extract_urls(text: str) -> List[str]:
    found = URL_PATTERN.findall(text)
    cleaned = []
    for u in found:
        u_clean = u.rstrip(".,);]'\"")
        if u_clean and u_clean not in cleaned:
            cleaned.append(u_clean)
    return cleaned

def parse_msg_file(raw_data: bytes) -> Dict[str, Any]:
    """Parse Microsoft Outlook .msg (OLE compound format) file."""
    if not extract_msg:
        raise ValueError("extract_msg library not installed")
    
    msg = extract_msg.Message(io.BytesIO(raw_data))
    subject = str(msg.subject or '')
    sender = str(msg.sender or '')
    to = str(msg.to or '')
    cc = str(msg.cc or '')
    date_header = str(msg.date or '')
    message_id = str(getattr(msg, 'messageId', '') or '')
    reply_to = ''
    return_path = ''

    body_plain = str(msg.body or '')
    body_html = ''
    if hasattr(msg, 'htmlBody') and msg.htmlBody:
        if isinstance(msg.htmlBody, bytes):
            try:
                body_html = msg.htmlBody.decode('utf-8', errors='replace')
            except Exception:
                body_html = ''
        else:
            body_html = str(msg.htmlBody)

    attachments = []
    if hasattr(msg, 'attachments'):
        for att in msg.attachments:
            try:
                fname = att.longFilename or att.shortFilename or 'attachment.bin'
                data = att.data or b''
                md5_hash = hashlib.md5(data).hexdigest()
                sha256_hash = hashlib.sha256(data).hexdigest()
                attachments.append({
                    'filename': fname,
                    'content_type': getattr(att, 'mimetype', 'application/octet-stream') or 'application/octet-stream',
                    'size': len(data),
                    'size_bytes': len(data),
                    'md5': md5_hash,
                    'sha256': sha256_hash
                })
            except Exception:
                pass

    received_headers = []
    headers_dict = {}
    if hasattr(msg, 'header') and msg.header:
        header_str = str(msg.header)
        for line in header_str.splitlines():
            if line.lower().startswith('received:'):
                received_headers.append(line[9:].strip())
            elif line.lower().startswith('return-path:'):
                return_path = line[12:].strip()
            elif line.lower().startswith('reply-to:'):
                reply_to = line[9:].strip()
            elif ':' in line and not line.startswith(' ') and not line.startswith('\t'):
                parts = line.split(':', 1)
                headers_dict[parts[0].strip()] = parts[1].strip()

    clean_text = body_plain
    if not clean_text and body_html:
        clean_text = re.sub(r'<[^>]+>', ' ', body_html)
        clean_text = re.sub(r'\s+', ' ', clean_text).strip()

    combined_for_urls = (body_plain or '') + ' ' + (body_html or '')
    urls = extract_urls(combined_for_urls)

    return {
        'subject': subject,
        'from': sender,
        'to': to,
        'cc': cc,
        'date': date_header,
        'message_id': message_id,
        'reply_to': reply_to,
        'return_path': return_path,
        'body_plain': body_plain,
        'body_html': body_html,
        'clean_text': clean_text,
        'urls': urls,
        'attachments': attachments,
        'received_headers': received_headers,
        'all_headers': headers_dict
    }

def parse_email_content(raw_data: bytes) -> Dict[str, Any]:
    # Check if this is a binary Outlook .msg file (OLE Compound File format: D0 CF 11 E0 A1 B1 1A E1)
    if raw_data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1') and extract_msg:
        try:
            return parse_msg_file(raw_data)
        except Exception:
            pass  # Fall back to standard MIME parser

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_data)
    except Exception:
        try:
            msg = email.message_from_bytes(raw_data)
        except Exception:
            text_content = raw_data.decode('utf-8', errors='replace')
            msg = email.message_from_string(text_content)

    subject = str(msg.get('Subject', '') or '')
    sender = str(msg.get('From', '') or '')
    to = str(msg.get('To', '') or '')
    cc = str(msg.get('Cc', '') or '')
    date_header = str(msg.get('Date', '') or '')
    message_id = str(msg.get('Message-ID', '') or '')
    reply_to = str(msg.get('Reply-To', '') or '')
    return_path = str(msg.get('Return-Path', '') or '')

    body_plain = ''
    body_html = ''
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', ''))

            if 'attachment' in content_disposition or part.get_filename():
                filename = part.get_filename() or 'unnamed_attachment'
                payload = part.get_payload(decode=True) or b''
                md5_hash = hashlib.md5(payload).hexdigest()
                sha256_hash = hashlib.sha256(payload).hexdigest()
                attachments.append({
                    'filename': filename,
                    'content_type': content_type,
                    'size': len(payload),
                    'md5': md5_hash,
                    'sha256': sha256_hash
                })
            else:
                if content_type == 'text/plain' and not body_plain:
                    try:
                        body_plain = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        body_plain = payload.decode(errors='replace') if payload else ''
                elif content_type == 'text/html' and not body_html:
                    try:
                        body_html = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        body_html = payload.decode(errors='replace') if payload else ''
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            content = payload.decode(errors='replace') if payload else ''
            
        if content_type == 'text/html':
            body_html = content
        else:
            body_plain = content

    clean_text = body_plain
    if not clean_text and body_html:
        clean_text = re.sub(r'<[^>]+>', ' ', body_html)
        clean_text = re.sub(r'\s+', ' ', clean_text).strip()

    combined_for_urls = (body_plain or '') + ' ' + (body_html or '')
    urls = extract_urls(combined_for_urls)

    received_headers = msg.get_all('Received', []) or []
    if isinstance(received_headers, str):
        received_headers = [received_headers]

    headers_dict = {}
    for k, v in msg.items():
        if k in headers_dict:
            if isinstance(headers_dict[k], list):
                headers_dict[k].append(str(v))
            else:
                headers_dict[k] = [headers_dict[k], str(v)]
        else:
            headers_dict[k] = str(v)

    return {
        'subject': subject,
        'from': sender,
        'to': to,
        'cc': cc,
        'date': date_header,
        'message_id': message_id,
        'reply_to': reply_to,
        'return_path': return_path,
        'body_plain': body_plain,
        'body_html': body_html,
        'clean_text': clean_text,
        'urls': urls,
        'attachments': attachments,
        'received_headers': received_headers,
        'all_headers': headers_dict
    }
