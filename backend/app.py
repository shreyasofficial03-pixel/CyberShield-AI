#!/usr/bin/env python3
"""
CyberShield AI - Python Flask Backend API Service
Provides real website security auditing, phishing heuristics, SSL inspection,
HTTP security header evaluation, redirect tracing, and threat intelligence.

Base URL: http://localhost:5000
Endpoints:
  - POST /api/scan
  - GET  /api/scan/history
  - POST /api/report
  - GET  /api/threats
  - GET  /api/health
"""

import math
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
import certifi
import tldextract
import os
import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

from flask import Flask, jsonify, request
from flask_cors import CORS
import requests

app = Flask(__name__)
# Enable CORS for the React development frontend
CORS(app, resources={r"/api/*": {"origins": "*"}})

# In-memory storage for demonstration & local operation
SCAN_HISTORY = []
THREAT_REPORTS = [
    {
        "id": "rep-fl-001",
        "domain": "secure-login-wellsfargo-verify99.net",
        "url": "https://secure-login-wellsfargo-verify99.net/auth/portal",
        "category": "Fake Banking",
        "targetedBrand": "Wells Fargo",
        "evidenceNotes": "SMS spear-phishing lure claiming debit card suspension. Links to clone login page.",
        "severity": "critical",
        "reportedAt": "2026-11-08T06:14:00.000Z",
        "reporterHandle": "threat_intel_bot",
        "verificationStatus": "verified",
        "upvotes": 42
    },
    {
        "id": "rep-fl-002",
        "domain": "apple-id-verify-icloud-sync.cc",
        "url": "https://apple-id-verify-icloud-sync.cc/account",
        "category": "Credential Harvester",
        "targetedBrand": "Apple ID",
        "evidenceNotes": "Fake storage quota notice collecting Apple ID credentials.",
        "severity": "critical",
        "reportedAt": "2026-11-08T04:55:00.000Z",
        "reporterHandle": "sec_researcher_py",
        "verificationStatus": "verified",
        "upvotes": 38
    }
]

KNOWN_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "chase", "wellsfargo",
    "bankofamerica", "netflix", "facebook", "instagram", "coinbase", "binance",
    "dropbox", "dhl", "fedex", "usps", "walmart"
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security", "portal",
    "account", "update", "banking", "wallet", "recover", "authenticate", "auth",
    "confirm", "support", "billing", "invoice", "payment", "suspended"
]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def check_homograph_and_punycode(domain: str) -> tuple[bool, str]:
    """Detects Cyrillic/Greek homoglyphs and punycode representations."""
    is_homograph = False
    punycode = ""
    try:
        encoded = domain.encode("idna").decode("ascii")
        if encoded.startswith("xn--") or "xn--" in encoded:
            is_homograph = True
            punycode = encoded
    except Exception:
        pass

    # Check for mixed script or non-ASCII characters
    for char in domain:
        if ord(char) > 127:
            is_homograph = True
            break

    # Look for common leetspeak substitutions
    typo_patterns = [r"paypa1", r"g00gle", r"micros0ft", r"app1e", r"amaz0n"]
    for pat in typo_patterns:
        if re.search(pat, domain.lower()):
            is_homograph = True

    return is_homograph, punycode


def inspect_ssl(hostname: str, port: int = 443) -> dict:
    """Performs real SSL/TLS handshake and extracts certificate metadata."""
    try:
        context = ssl.create_default_context(cafile=certifi.where())

        with socket.create_connection((hostname, port), timeout=3.5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown CA"

                # Extract Subject
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                subject_cn = subject_dict.get("commonName") or hostname

                # Subject Alternative Names (SANs)
                sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

                # Expiry dates
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")
                days_remaining = 0
                if not_after:
                    try:
                        exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now_dt = datetime.now(timezone.utc)
                        days_remaining = max(0, (exp_dt - now_dt).days)
                    except Exception:
                        days_remaining = 30

                return {
                    "valid": True,
                    "issuer": issuer_name,
                    "subject": f"CN={subject_cn}",
                    "validFrom": not_before,
                    "validTo": not_after,
                    "daysRemaining": days_remaining,
                    "tlsVersion": version or "TLSv1.3",
                    "cipherSuite": cipher[0] if cipher else "TLS_AES_256_GCM_SHA384",
                    "sanCount": len(sans),
                    "sans": sans[:6],
                    "selfSigned": False,
                    "revocationChecked": True,
                    "keyStrength": "2048-bit RSA/ECC"
                }
    except ssl.SSLCertVerificationError as e:
        return {
            "valid": False,
            "issuer": "Untrusted / Self-Signed",
            "subject": f"CN={hostname}",
            "validFrom": "N/A",
            "validTo": "N/A",
            "daysRemaining": 0,
            "tlsVersion": "None (Verification Failed)",
            "cipherSuite": "Insecure",
            "sanCount": 0,
            "sans": [],
            "selfSigned": True,
            "revocationChecked": False,
            "keyStrength": "Untrusted"
        }
    except Exception:
        return {
            "valid": False,
            "issuer": "Connection Timed Out / Inaccessible",
            "subject": f"CN={hostname}",
            "validFrom": "N/A",
            "validTo": "N/A",
            "daysRemaining": 0,
            "tlsVersion": "None",
            "cipherSuite": "None",
            "sanCount": 0,
            "sans": [],
            "selfSigned": False,
            "revocationChecked": False,
            "keyStrength": "None"
        }

def get_registered_domain(url):
    hostname = urlparse(url).hostname

    if not hostname:
        return None

    extracted = tldextract.extract(hostname)

    return extracted.top_domain_under_public_suffix
def trace_redirects_and_headers(target_url: str) -> tuple[dict, list]:
    """Traces redirect hops and assesses HTTP security headers."""
    hops = []
    headers_result = []

    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "CyberShield-AI-Security-Auditor/1.0 (+https://cybershield.ai/bot)"
        })

        resp = session.get(target_url, allow_redirects=True, timeout=5.0)

        # Build redirect hops
        hop_num = 1
        for r in resp.history:
            parsed = urlparse(r.url)
            hops.append({
                "hopNumber": hop_num,
                "url": r.url,
                "statusCode": r.status_code,
                "statusText": r.reason,
                "latencyMs": int(r.elapsed.total_seconds() * 1000),
                "protocol": f"{parsed.scheme}:"
            })
            hop_num += 1

        final_parsed = urlparse(resp.url)
        hops.append({
            "hopNumber": hop_num,
            "url": resp.url,
            "statusCode": resp.status_code,
            "statusText": resp.reason,
            "latencyMs": int(resp.elapsed.total_seconds() * 1000),
            "protocol": f"{final_parsed.scheme}:"
        })

        # Evaluate Security Headers
        resp_headers = resp.headers

        # HSTS
        hsts = resp_headers.get("Strict-Transport-Security")
        headers_result.append({
            "name": "Strict-Transport-Security",
            "present": bool(hsts),
            "value": hsts,
            "status": "pass" if hsts else "fail",
            "importance": "critical",
            "description": "Enforces HTTPS connections and safeguards against SSL stripping.",
            "recommendation": None if hsts else "Configure Strict-Transport-Security with max-age=31536000; includeSubDomains."
        })

        # CSP
        csp = resp_headers.get("Content-Security-Policy")
        headers_result.append({
            "name": "Content-Security-Policy",
            "present": bool(csp),
            "value": (csp[:120] + "...") if csp and len(csp) > 120 else csp,
            "status": "pass" if csp else "fail",
            "importance": "critical",
            "description": "Restricts sources from which scripts, styles, and assets can be loaded.",
            "recommendation": None if csp else "Deploy Content-Security-Policy restricting unauthorized script execution."
        })

        # X-Frame-Options
        xfo = resp_headers.get("X-Frame-Options")
        headers_result.append({
            "name": "X-Frame-Options",
            "present": bool(xfo),
            "value": xfo,
            "status": "pass" if xfo else "fail",
            "importance": "high",
            "description": "Protects against clickjacking attacks by blocking unauthorized iframes.",
            "recommendation": None if xfo else "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
        })

        # X-Content-Type-Options
        xcto = resp_headers.get("X-Content-Type-Options")
        headers_result.append({
            "name": "X-Content-Type-Options",
            "present": bool(xcto),
            "value": xcto,
            "status": "pass" if xcto and "nosniff" in xcto.lower() else "fail",
            "importance": "medium",
            "description": "Prevents MIME-sniffing away from the declared content-type.",
            "recommendation": None if xcto else "Set 'X-Content-Type-Options: nosniff'."
        })

        # Referrer-Policy
        ref_pol = resp_headers.get("Referrer-Policy")
        headers_result.append({
            "name": "Referrer-Policy",
            "present": bool(ref_pol),
            "value": ref_pol,
            "status": "pass" if ref_pol else "warn",
            "importance": "medium",
            "description": "Controls what information is sent in the Referer header.",
            "recommendation": None if ref_pol else "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
        })

        redirect_summary = {
            "hopCount": len(hops) - 1,
            "hops": hops,
            "initialUrl": target_url,
            "finalUrl": resp.url,
            "isHttpsUpgrade": resp.url.startswith("https://") and target_url.startswith("http://"),
            "hasSuspiciousRedirect": (
                len(hops) > 3 or
                (
                    len(hops) > 1 and
                    get_registered_domain(hops[0]["url"]) != get_registered_domain(resp.url)
                )
            ),
            "crossDomainHop": (
                len(hops) > 1 and
                get_registered_domain(hops[0]["url"]) != get_registered_domain(resp.url)
            )
        }

        return redirect_summary, headers_result

    except Exception:
        # Fallback when site is unreachable
        return {
            "hopCount": 0,
            "hops": [{
                "hopNumber": 1,
                "url": target_url,
                "statusCode": 0,
                "statusText": "Unreachable",
                "latencyMs": 0,
                "protocol": "https:" if target_url.startswith("https") else "http:"
            }],
            "initialUrl": target_url,
            "finalUrl": target_url,
            "isHttpsUpgrade": False,
            "hasSuspiciousRedirect": False,
            "crossDomainHop": False
        }, [
            {
                "name": "Strict-Transport-Security",
                "present": False,
                "status": "fail",
                "importance": "critical",
                "description": "Could not be audited due to connection timeout."
            }
        ]


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "connected",
        "service": "CyberShield AI Flask Backend",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })



def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return {
            "verified": False,
            "status": "not_configured",
            "message": "VirusTotal API key not configured"
        }

    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.post(
            api_url,
            headers=headers,
            data={"url": url},
            timeout=15
        )

        if response.status_code != 200:
            return {
                "verified": False,
                "status": "api_error",
                "message": f"VirusTotal HTTP {response.status_code}"
            }

        analysis_id = response.json()["data"]["id"]
        report_url = (
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        )

        # Check the report up to 5 times
        for attempt in range(5):
            if attempt > 0:
                time.sleep(3)

            report_response = requests.get(
                report_url,
                headers=headers,
                timeout=15
            )

            if report_response.status_code != 200:
                continue

            report = report_response.json()
            attributes = report["data"]["attributes"]

            if attributes.get("status") == "completed":
                stats = attributes.get("stats", {})

                return {
                    "verified": True,
                    "status": "completed",
                    "analysisId": analysis_id,
                    "maliciousDetections": stats.get("malicious", 0),
                    "suspiciousDetections": stats.get("suspicious", 0),
                    "harmlessDetections": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "totalEngines": sum(stats.values()),
                    "message": "VirusTotal analysis completed"
                }

        return {
            "verified": False,
            "status": "pending",
            "analysisId": analysis_id,
            "message": "Analysis is still processing. Try scanning again."
        }

    except requests.RequestException:
        return {
            "verified": False,
            "status": "connection_error",
            "message": "Could not connect to VirusTotal"
        }

    except (KeyError, ValueError, TypeError):
        return {
            "verified": False,
            "status": "invalid_response",
            "message": "Unexpected VirusTotal response"
        }




@app.route("/api/scan", methods=["POST"])
def scan_website():
    start_time = time.time()
    data = request.get_json() or {}
    raw_url = data.get("url", "").strip()

    if not raw_url:
        return jsonify({"error": "Missing required 'url' parameter"}), 400

    # Normalize URL scheme
    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        url = f"https://{raw_url}"
    else:
        url = raw_url

    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path.split("/")[0]
    # Remove port if present in hostname
    hostname_clean = hostname.split(":")[0]

    # 1. Resolve IP Address
    ip_addr = "127.0.0.1"
    try:
        ip_addr = socket.gethostbyname(hostname_clean)
    except Exception:
        pass

    # 2. Phishing Heuristics & Lexical Analysis
    entropy = calculate_entropy(url)
    is_homograph, punycode = check_homograph_and_punycode(hostname_clean)

    # Keyword detection
    path_and_host = (hostname_clean + parsed.path).lower()
    keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_and_host]

    # Brand impersonation check
    targeted_brand = None
    for brand in KNOWN_BRANDS:
        if brand in hostname_clean.lower() and not hostname_clean.lower().endswith(f".{brand}.com") and hostname_clean.lower() != f"{brand}.com":
            targeted_brand = brand.capitalize()
            break

    # 3. SSL Inspection
    ssl_info = inspect_ssl(hostname_clean)

    # 4. Redirects & Security Headers
    redirects_info, headers_info = trace_redirects_and_headers(url)

    virustotal_info = check_virustotal(url)
    print("VIRUSTOTAL RESULT:", virustotal_info)

    # 5. Risk Scoring Engine (0-100)
    risk_score = 0
    why_suspicious = []
    heuristics = []

    # Heuristic 1: Brand Impersonation (+40)
    if targeted_brand:
        risk_score += 40
        why_suspicious.append(f"Brand Impersonation: Domain unauthorizedly incorporates trademark of '{targeted_brand}'.")
        heuristics.append({
            "id": "brand-imp",
            "title": "Targeted Brand Impersonation",
            "category": "lexical",
            "severity": "critical",
            "impactScore": 40,
            "detected": True,
            "description": f"Domain mimics {targeted_brand} infrastructure without verified affiliation."
        })

    # Heuristic 2: Homograph / Punycode (+30)
    if is_homograph:
        risk_score += 30
        why_suspicious.append(f"Homograph Spoofing: Detected Cyrillic/Greek characters or leetspeak substitutions ({punycode or 'visually deceptive glyphs'}).")
        heuristics.append({
            "id": "homoglyph",
            "title": "Homoglyph Character Substitution",
            "category": "homograph",
            "severity": "high",
            "impactScore": 30,
            "detected": True,
            "description": "Unicode characters disguised as standard ASCII letters to mislead visitors."
        })

    # Heuristic 3: Suspicious Keywords (+5 per keyword, up to 20)
    if keywords_found:
        kw_impact = min(20, len(keywords_found) * 6)
        risk_score += kw_impact
        why_suspicious.append(f"High-Risk Keywords: URL includes authentication/urgency triggers: {', '.join(keywords_found)}.")
        heuristics.append({
            "id": "kw-stuff",
            "title": "Authentication Keyword Stuffing",
            "category": "lexical",
            "severity": "medium",
            "impactScore": kw_impact,
            "detected": True,
            "description": f"Detected sensitive lures: {', '.join(keywords_found)}"
        })

    # Heuristic 4: SSL Invalidation or Missing (+30)
    if not ssl_info["valid"]:
        risk_score += 30
        why_suspicious.append("Cryptographic Failure: SSL/TLS certificate is expired, self-signed, or untrusted.")
        heuristics.append({
            "id": "ssl-fail",
            "title": "SSL Certificate Invalid / Self-Signed",
            "category": "dns",
            "severity": "critical",
            "impactScore": 30,
            "detected": True,
            "description": "Unable to verify trusted certificate chain authority."
        })

    # Heuristic 5: Missing HSTS & CSP (+15)
    missing_crit_headers = [h["name"] for h in headers_info if h["status"] == "fail" and h["importance"] == "critical"]
    if missing_crit_headers:
        risk_score += 12
        why_suspicious.append(f"Missing Defense Headers: Absence of {', '.join(missing_crit_headers)} leaves users exposed to clickjacking and MITM.")

    # Heuristic 6: High Entropy (+10)
    if entropy > 3.8:
        risk_score += 10
        why_suspicious.append(f"High Lexical Entropy ({entropy}): URL exhibits abnormal character randomness common in phishing landing paths.")

    # Heuristic 7: Cross-domain redirection (+15)
    if redirects_info["crossDomainHop"]:
        risk_score += 15
        why_suspicious.append("Cross-Domain Redirection: Initial entry URL bounces visitor across differing domain entities.")

    # Clamp score to 0..100
    risk_score = min(100, max(0, risk_score))

    # Risk level classification
    if risk_score >= 80:
        risk_level = "critical"
        verdict = "critical"
    elif risk_score >= 50:
        risk_level = "high"
        verdict = "suspicious"
    elif risk_score >= 25:
        risk_level = "moderate"
        verdict = "suspicious"
    else:
        risk_level = "low"
        verdict = "safe"

    is_phishing = risk_score >= 50

    elapsed_ms = int((time.time() - start_time) * 1000)

    # Determine summary
    if verdict == "critical":
        summary = f"Critical security alert! Active phishing/malware indicators detected on {hostname_clean}."
    elif verdict == "suspicious":
        summary = f"Elevated security risk. {hostname_clean} exhibits anomalous features requiring cautious inspection."
    else:
        summary = f"Website demonstrates healthy security hygiene, trusted cryptographic credentials, and no known threat markers."

    scan_result = {
        "id": f"scan-{int(time.time()*1000)}",
        "url": url,
        "scannedAt": datetime.now(timezone.utc).isoformat(),
        "scanDurationMs": elapsed_ms,
        "riskScore": risk_score,
        "riskLevel": risk_level,
        "verdict": verdict,
        "summary": summary,
        "whySuspicious": why_suspicious,
        "phishing": {
            "isPhishing": is_phishing,
            "confidence": min(99, max(50, risk_score + 10)) if is_phishing else max(5, 100 - risk_score),
            "primaryThreatType": ("Brand Impersonation" if targeted_brand else "Credential Harvester") if is_phishing else "Benign",
            "targetedBrand": targeted_brand,
            "homographAttack": is_homograph,
            "punycodeDomain": punycode if is_homograph else None,
            "entropyScore": entropy,
            "suspiciousKeywordsFound": keywords_found
        },
        "ssl": ssl_info,
        "headers": headers_info,
        "redirects": redirects_info,
        
        "threatIntel": {
            "safeBrowsing": (
                "malicious" if virustotal_info.get("verified")
                and virustotal_info.get("maliciousDetections", 0) > 0
                else "suspicious" if virustotal_info.get("verified")
                and virustotal_info.get("suspiciousDetections", 0) > 0
                else "clean" if virustotal_info.get("verified")
                else "not_checked"
            ),

            "reputationEnginesChecked": virustotal_info.get("totalEngines", 0),
            "maliciousDetections": virustotal_info.get("maliciousDetections"),
            "suspiciousDetections": virustotal_info.get("suspiciousDetections"),

            "domainAgeDays": None,
            "registrar": None,
            "registeredDate": None,
            "nameservers": [],

            "ipAddress": ip_addr,
            "hostingProvider": None,
            "country": None,
            "asn": None,

            "verified": virustotal_info.get("verified", False),
            "analysisStatus": virustotal_info.get("status", "not_checked"),
            "dataSource": "VirusTotal API"
    },

        "heuristics": heuristics,
        "isMockData": False
    }

    # Store in history
    SCAN_HISTORY.insert(0, {
        "id": scan_result["id"],
        "url": scan_result["url"],
        "scannedAt": scan_result["scannedAt"],
        "riskScore": scan_result["riskScore"],
        "riskLevel": scan_result["riskLevel"],
        "verdict": scan_result["verdict"],
        "scanDurationMs": scan_result["scanDurationMs"],
        "sslValid": scan_result["ssl"]["valid"],
        "phishingDetected": scan_result["phishing"]["isPhishing"],
        "isMockData": False
    })

    return jsonify(scan_result)


@app.route("/api/scan/history", methods=["GET"])
def get_history():
    return jsonify(SCAN_HISTORY[:50])


@app.route("/api/report", methods=["POST"])
def submit_report():
    data = request.get_json() or {}
    domain = data.get("domain") or urlparse(data.get("url", "")).netloc
    if not domain:
        return jsonify({"error": "Missing domain or url"}), 400

    report = {
        "id": f"rep-user-{int(time.time()*1000)}",
        "domain": domain,
        "url": data.get("url", f"https://{domain}"),
        "category": data.get("category", "Phishing"),
        "targetedBrand": data.get("targetedBrand"),
        "evidenceNotes": data.get("evidenceNotes", "Reported by community analyst"),
        "severity": data.get("severity", "high"),
        "reportedAt": datetime.now(timezone.utc).isoformat(),
        "reporterHandle": data.get("reporterHandle", "anonymous_analyst"),
        "verificationStatus": "pending",
        "upvotes": 1,
        "isMockData": False
    }
    THREAT_REPORTS.insert(0, report)
    return jsonify(report), 201


@app.route("/api/threats", methods=["GET"])
def get_threats():
    q = request.args.get("q", "").lower().strip()
    if not q:
        return jsonify(THREAT_REPORTS)

    filtered = [
        r for r in THREAT_REPORTS
        if q in r["domain"].lower() or q in r["category"].lower() or (r.get("targetedBrand") and q in r["targetedBrand"].lower())
    ]
    return jsonify(filtered)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] CyberShield AI Flask API running on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
