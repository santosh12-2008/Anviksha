import base64
import urllib.parse
import requests
from typing import Dict, Any, List, Optional
from app.core.config import settings

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
GMAIL_MESSAGES_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages"

def get_google_auth_url() -> str:
    """Generates the Google OAuth 2.0 consent URL for Gmail read-only access."""
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
        "access_type": "offline",
        "prompt": "consent"
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"

def exchange_code_for_tokens(code: str) -> Dict[str, Any]:
    """Exchanges an authorization code for Google access and refresh tokens."""
    payload = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(GOOGLE_TOKEN_URL, data=payload, headers=headers, timeout=10)
    
    if response.status_code != 200:
        error_detail = response.json().get("error_description", response.text)
        raise ValueError(f"Google OAuth token exchange failed: {error_detail}")
    
    return response.json()

def get_google_user_profile(access_token: str) -> Dict[str, Any]:
    """Retrieves Google account profile information."""
    headers = {"Authorization": f"Bearer {access_token}"}
    res = requests.get(GOOGLE_USERINFO_URL, headers=headers, timeout=10)
    if res.status_code != 200:
        raise ValueError("Failed to fetch Google user profile")
    return res.json()

def list_gmail_messages(access_token: str, max_results: int = 12) -> List[Dict[str, Any]]:
    """Fetches incoming message list from the user's live Gmail account."""
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"maxResults": max_results, "q": "label:INBOX"}
    res = requests.get(GMAIL_MESSAGES_URL, headers=headers, params=params, timeout=12)
    
    if res.status_code != 200:
        raise ValueError(f"Gmail API list messages failed ({res.status_code}): {res.text}")
    
    data = res.json()
    return data.get("messages", [])

def get_gmail_message_raw(access_token: str, message_id: str) -> bytes:
    """
    Fetches the complete RFC 822 raw email data for a message.
    Decodes Google's URL-safe base64 string into raw bytes.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{GMAIL_MESSAGES_URL}/{message_id}?format=raw"
    res = requests.get(url, headers=headers, timeout=12)
    
    if res.status_code != 200:
        raise ValueError(f"Failed to fetch raw message {message_id}: {res.text}")
    
    raw_b64 = res.json().get("raw", "")
    # Decode URL-safe base64
    return base64.urlsafe_b64decode(raw_b64.encode("utf-8"))

def get_gmail_message_metadata(access_token: str, message_id: str) -> Dict[str, Any]:
    """Fetches lightweight headers (Subject, From, Date) and snippet for inbox display."""
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{GMAIL_MESSAGES_URL}/{message_id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date"
    res = requests.get(url, headers=headers, timeout=10)
    
    if res.status_code != 200:
        return {"id": message_id, "subject": "Email", "sender": "Unknown", "snippet": ""}
    
    data = res.json()
    header_list = data.get("payload", {}).get("headers", [])
    header_dict = {h["name"].lower(): h["value"] for h in header_list}
    
    return {
        "id": message_id,
        "thread_id": data.get("threadId"),
        "subject": header_dict.get("subject", "(No Subject)"),
        "sender": header_dict.get("from", "Unknown"),
        "date": header_dict.get("date", "Recent"),
        "snippet": data.get("snippet", "")
    }
