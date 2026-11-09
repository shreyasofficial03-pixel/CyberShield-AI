# CyberShield AI - Python Flask Backend

This directory contains the Python Flask backend service for the **CyberShield AI** phishing detection and website security assessment platform.

## Quickstart

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Flask API Server
```bash
python app.py
```
The server will start at `http://localhost:5000`.

## API Endpoints

- `GET /api/health`
  Returns server health status, version, and timestamp.

- `POST /api/scan`
  Conducts website inspection: DNS resolution, SSL handshake, redirect hop tracing, HTTP security headers, lexical/homograph phishing heuristic evaluation, and risk scoring (0-100).
  **Payload:**
  ```json
  {
    "url": "https://example.com",
    "options": {
      "deepSsl": true,
      "traceRedirects": true,
      "threatDbLookup": true
    }
  }
  ```

- `GET /api/scan/history`
  Returns the latest website scans performed.

- `POST /api/report`
  Submit a suspicious domain or active phishing link.
  **Payload:**
  ```json
  {
    "url": "https://fake-bank-login.xyz",
    "domain": "fake-bank-login.xyz",
    "category": "Fake Banking",
    "targetedBrand": "Chase Bank",
    "severity": "critical",
    "evidenceNotes": "Credential harvest page targeting account holders",
    "reporterHandle": "sec_researcher"
  }
  ```

- `GET /api/threats?q=searchterm`
  Returns community and threat intelligence database reports.
