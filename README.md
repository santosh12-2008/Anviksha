# Anviksha (अन्वीक्षा) - AI Email Threat Detection, Geolocation & Forensic Intelligence Platform

**Anviksha (अन्वीक्षा)** is a next-generation AI-powered email threat detection, geographic origin attribution, and deep forensic intelligence platform. It bridges the gap between deep SOC forensic analysis and non-technical end-user protection.

---

## 🌟 Key Features

1. **Authentication & Ingestion Modes**:
   - **Google Sign-In / Gmail API Integration**: Connects to the user's Gmail inbox to review incoming messages or run a batch security triage across the entire inbox.
   - **Guest Mode (Manual Scan)**: Direct file upload supporting `.eml`, `.msg`, `.mbox`, and `.txt` files or raw RFC 822 text paste without requiring registration.
   - **Enterprise SOC Analyst Portal**: Full credential login with pre-seeded demo accounts (`analyst` and `admin`).

2. **Inbox-Wide Batch Security Scanner & Threat Triage**:
   - 1-Click **"Analyze All Emails in Inbox"** scans all messages simultaneously.
   - Assigns tri-color threat indicators:
     - 🔴 **Red**: Critical / High Threat (Phishing lures, BEC fraud, ransomware payloads, Tor exit nodes).
     - 🟡 **Yellow**: Suspicious / Caution (Urgent social engineering, unverified routing, suspicious domains).
     - 🔵 **Blue**: Safe / Verified Legitimate (Passed SPF/DKIM/DMARC, authentic infrastructure).
   - Real-time **Summary Metrics Dashboard** reporting exact counts of Red, Yellow, and Blue emails with one-click filter pills.

3. **Two-Tier Report Architecture**:
   - **User-Friendly Report (Default)**:
     - Visual danger verdict badge (🔴 DANGEROUS / 🟡 SUSPICIOUS / 🔵 SAFE).
     - 0–100 circular Risk Meter.
     - **AI Executive Summary**: Plain-English breakdown explaining the email's premise and hidden attacker goal so users don't have to read lures.
     - **Layman Risk Factors**: Clear bullet-point reasons why the email was flagged.
     - **Immediate Action Steps**: Concrete checklist ("What should you do right now?").
     - Origin location badge (e.g., "Origin: Frankfurt, Germany [Tor Anonymizer Network]").
   - **Expert SOC Forensic Dossier (Deep Technical View)**:
     - Hop-by-hop relay route map using Leaflet.js with transmission delay telemetry.
     - Cryptographic verification matrix (SPF, DKIM, DMARC, ARC).
     - Raw RFC 822 headers inspector with search and anomaly flags.
     - Indicators of Compromise (IOC) table with SHA-256 hashes, defanged URLs, and JSON/STIX export.
     - Domain intelligence and WHOIS age telemetry.

4. **Community Defense & Victim Experience Sharing**:
   - **Similarity Match Alert**: When an email is analyzed, Anviksha searches community incident reports and alerts the user if other defenders were targeted by the same scheme.
   - **Share Your Experience Form**: Allows users to publish their attack story, loss avoided, and warning signs to protect others globally.

5. **Predictive Contextual FAQ & Jargon Buster**:
   - Dynamic questions and answers based on the detected threat (e.g., *"What if I clicked?", "Can my PC get infected?", "Why does the trace show Germany?"*).
   - Interactive **Jargon Buster** modal explaining SPF, DKIM, DMARC, ASN, Tor, Typosquatting, and Quishing with simple analogies.

6. **Light & Dark Mode**:
   - Modern theme engine stored in local storage supporting dark cybersecurity aesthetics and clean light mode.

7. **Domain & Threat Reporting**:
   - Form allowing users to report suspicious domains or sender addresses to the central threat database.

---

## 🚀 Quick Start Guide

### 1. Pre-Configured Analyst Login Credentials
| Role | Username | Password | Privileges |
| :--- | :--- | :--- | :--- |
| **SOC Threat Analyst** | `analyst` | `Analyst@2026!` | Dissect emails, view relay maps, export dossiers |
| **Chief Incident Admin** | `admin` | `Admin@2026!` | Full platform administration, API vault management |
| **Guest User** | *None required* | *None required* | Direct upload, manual paste, batch inbox scan |

---

### 2. Running the Servers

#### Option A: 1-Click Launch (Windows)
Double-click `start_all.bat`.

#### Option B: Terminal Commands
**Terminal 1 (Backend):**
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 (Frontend):**
```bash
cd frontend
npm run dev
```

- Web Portal: **http://127.0.0.1:5173/**
- API Docs: **http://127.0.0.1:8000/docs**

---

### 3. Preloaded Incident Fixtures for Instant Testing
1. 🚨 **PayPal Account Limited**: Phishing lure routed via Tor exit node in Frankfurt, Germany.
2. 💰 **CEO Wire Transfer Request**: Executive impersonation BEC from Nigerian ISP (Spectranet).
3. 📦 **DHL Express Waybill Trojan**: Camouflaged double-extension executable payload (`.pdf.exe`).
4. 📱 **Microsoft 365 MFA Quishing**: QR code lure bypassing text spam filters.
5. 🛡️ **Clean O365 / GitHub Digest**: Fully authenticated enterprise notifications (Blue / Safe).
