# ==========================================
# IMPORTS
# Standard library and third-party dependencies
# ==========================================
import email
import hashlib
import ipaddress
import re
import json
import os
from html.parser import HTMLParser
from urllib.parse import urlparse
from datetime import datetime, timezone

import cv2
import numpy as np
from pyzbar.pyzbar import decode as decode_qr
from PIL import Image
import io

# ==========================================
# CONSTANTS & CONFIGURATION
# Rule definitions for phishing detection
# ==========================================
PHISHING_KEYWORDS = {
    "urgency": [
        "urgent",
        "immediately",
        "action required",
        "act now",
        "expires today",
        "expire today",
        "within 24 hours",
    ],
    "threat": [
        "suspended",
        "locked",
        "disabled",
        "terminated",
        "legal action",
        "account closure",
    ],
    "credential": [
        "password",
        "login",
        "sign in",
        "verify your account",
        "confirm your identity",
        "security verification",
    ],
    "money": [
        "payment",
        "invoice",
        "refund",
        "tax",
        "wire transfer",
        "bank account",
        "direct deposit",
        "direct debit",
    ],
    "reward": [
        "you won",
        "winner",
        "prize",
        "reward",
        "free",
        "cash prize",
        "gift card",
    ],
}

SUSPICIOUS_URL_WORDS = [
    "login",
    "signin",
    "secure",
    "verify",
    "verification",
    "auth",
    "mfa",
    "portal",
    "validate",
    "security",
    "invoice",
    "document",
    "file",
    "update",
    "account",
    "required",
    "action",
    "payment",
    "billing",
    "statement",
    "admin",
    "support",
    "service",
    "office",
    "cloud",
    "webmail",
    "app",
    "server",
    "manage",
    "recovery",
]

PROTECTED_BRANDS = {
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "linkedin": "linkedin.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
}

DANGEROUS_EXTENSIONS = [
    ".exe",
    ".vbs",
    ".js",
    ".scr",
    ".iso",
    ".xlsm",
    ".docm",
    ".bat",
    ".ps1",
    ".hta",
    ".jar",
    ".zip",
    ".rar",
    ".7z",
]


# ==========================================
# HELPER / UTILITY FUNCTIONS
# ==========================================
def normalize_message(message):
    """Clean and standardize input text for processing."""
    return message.lower().strip()


def detect_keywords(message, keywords):
    """Scan normalized text against a list of keyword patterns using word boundaries."""
    matches = []
    for keyword in keywords:
        pattern = r"\b" + re.escape(keyword) + r"\b"
        if re.search(pattern, message):
            matches.append(keyword)
    return matches


def is_ip_address(hostname):
    """Determine whether a hostname is a raw IP address."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_hostname(url):
    """Extract the hostname from a URL."""
    parsed = urlparse(url)
    return parsed.hostname


# ==========================================
# HEADER & SENDER ANALYSIS (PHASE 5 & 6)
# ==========================================
def parse_email_headers(raw_email_or_headers):
    """Extract key routing and authentication headers from raw MIME messages."""
    if isinstance(raw_email_or_headers, str):
        msg = email.message_from_string(raw_email_or_headers)
    else:
        msg = raw_email_or_headers

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    auth_results = msg.get("Authentication-Results", "").lower()

    sender_domain = ""
    match = re.search(r"@([\w.-]+)", from_header)
    if match:
        sender_domain = match.group(1).lower()

    return {
        "from": from_header,
        "reply_to": reply_to,
        "sender_domain": sender_domain,
        "auth_results": auth_results,
    }


def detect_display_name_spoofing(from_header):
    """Flag when a display name claims to be a tech giant but sends from an unofficial domain."""
    match = re.match(r"^(.*?)\s*<([^>]+)>$", from_header.strip())
    if not match:
        return None

    display_name = match.group(1).lower()
    sender_email = match.group(2).lower()
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

    for brand, official_domain in PROTECTED_BRANDS.items():
        if brand in display_name:
            if sender_domain != official_domain and not sender_domain.endswith("." + official_domain):
                return {
                    "brand": brand,
                    "reason": f"Display name claims '{brand.title()}' but email sent from '{sender_domain}'",
                    "risk_score": 45,
                }
    return None


def detect_brand_typosquatting(domain):
    """Detect brand string embedding or lookalike domains in links/senders."""
    if not domain:
        return None

    domain = domain.lower().strip()

    for brand, official_domain in PROTECTED_BRANDS.items():
        if domain == official_domain or domain.endswith("." + official_domain):
            continue

        if brand in domain:
            return {
                "brand": brand,
                "reason": f"Protected brand '{brand}' embedded in unofficial domain '{domain}'",
                "risk_score": 35,
            }

    return None


def check_tech_giant_dmarc(sender_domain, auth_results):
    """Enforce strict auth penalty for spoofed tech giant domains failing DMARC/SPF/DKIM."""
    if not sender_domain or not auth_results:
        return None

    for brand, official_domain in PROTECTED_BRANDS.items():
        if sender_domain == official_domain or sender_domain.endswith("." + official_domain):
            if "dmarc=fail" in auth_results or "spf=fail" in auth_results or "dkim=fail" in auth_results:
                return {
                    "brand": brand,
                    "reason": f"Sender claims official domain '{sender_domain}' but failed email authentication!",
                    "risk_score": 50,
                }
    return None


# ==========================================
# ATTACHMENT ANALYSIS (PHASE 7)
# ==========================================
def analyze_attachments(raw_email_string_or_msg):
    """Parse email attachments, generate SHA-256 hashes, and assess extension risk."""
    if isinstance(raw_email_string_or_msg, str):
        msg = email.message_from_string(raw_email_string_or_msg)
    else:
        msg = raw_email_string_or_msg

    attachment_results = []

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()

        if "attachment" in content_disposition or filename:
            if not filename:
                filename = "unnamed_attachment"

            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            sha256_hash = hashlib.sha256(payload).hexdigest()
            lower_filename = filename.lower()

            indicators = []
            risk_score = 0

            has_dangerous_extension = any(
                lower_filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS
            )
            if has_dangerous_extension:
                indicators.append("dangerous_file_extension")
                risk_score += 40

            filename_parts = lower_filename.split(".")
            if len(filename_parts) > 2:
                second_last_ext = "." + filename_parts[-2]
                last_ext = "." + filename_parts[-1]
                if last_ext in DANGEROUS_EXTENSIONS and second_last_ext in [".pdf", ".doc", ".docx", ".xlsx", ".txt", ".png", ".jpg"]:
                    indicators.append("double_extension_spoofing")
                    risk_score += 30

            attachment_results.append(
                {
                    "filename": filename,
                    "sha256": sha256_hash,
                    "size_bytes": len(payload),
                    "indicators": indicators,
                    "risk_score": risk_score,
                    "suspicious": risk_score > 0,
                }
            )

    return attachment_results


# ==========================================
# QR CODE (QUISHING) ANALYSIS (PHASE 8)
# ==========================================
def extract_qr_codes_from_bytes(image_bytes):
    """Decode QR code URLs from raw image byte streams using PyZBar."""
    extracted_urls = []
    try:
        # Open image with PIL directly
        image = Image.open(io.BytesIO(image_bytes))
        
        # PyZBar can decode PIL images directly!
        decoded_objects = decode_qr(image)
        for obj in decoded_objects:
            if obj.type == "QRCODE":
                qr_data = obj.data.decode("utf-8", errors="ignore").strip()
                if qr_data.startswith(("http://", "https://")):
                    extracted_urls.append(qr_data)
    except Exception as e:
        print(f"[DEBUG] QR Extraction Error: {e}")
    return extracted_urls


def analyze_email_qr_codes(raw_email_string_or_msg):
    """Scan all inline and attached images in a MIME message for QR code URLs (Quishing)."""
    if isinstance(raw_email_string_or_msg, str):
        msg = email.message_from_string(raw_email_string_or_msg)
    else:
        msg = raw_email_string_or_msg

    qr_results = []

    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type.startswith("image/"):
            payload = part.get_payload(decode=True)
            if not payload:
                continue

            extracted_urls = extract_qr_codes_from_bytes(payload)
            filename = part.get_filename() or "inline_image"

            for url in extracted_urls:
                url_eval = analyze_url(url)
                risk = calculate_unified_risk(url_eval)

                # Add a base quishing penalty for hiding destinations in QR codes
                quishing_risk_score = risk["score"] + 25

                qr_results.append(
                    {
                        "source_image": filename,
                        "qr_url": url,
                        "indicators": url_eval["indicators"] + ["embedded_qr_code"],
                        "risk_score": quishing_risk_score,
                        "severity": "high" if quishing_risk_score >= 50 else "medium",
                    }
                )

    return qr_results


# ==========================================
# PHASE 9: SIEM LOGGING & ANALYST REPORTING
# ==========================================

def export_json_log(results, risk_assessment, output_file="phishing_events.json"):
    """
    Exports structured detection telemetry into a single-line JSON log entry 
    compatible with Wazuh / Elastic / Splunk active log collectors.
    """
    log_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "phishing_detection_analysis",
        "verdict": risk_assessment["verdict"],
        "severity": risk_assessment["severity"].upper(),
        "total_risk_score": risk_assessment["score"],
        "suspicious_flag": results.get("detected", False),
        "text_categories": results.get("categories", []),
        "detections": {
            "header_anomalies": results.get("header_anomalies", []),
            "link_mismatches": results.get("mismatches", []),
            "suspicious_urls": results.get("suspicious_urls", []),
            "attachments": results.get("attachment_analysis", []),
            "quishing": results.get("qr_analysis", [])
        }
    }

    # Append as single-line NDJSON (Newline Delimited JSON) for log collectors
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_event) + "\n")

    print(f"[+] Structured JSON log successfully appended to '{output_file}'")
    return log_event


def generate_analyst_report(results, risk_assessment, output_file="analyst_report.html"):
    """
    Generates a standalone, styled HTML investigation report for SOC analysts.
    """
    severity = risk_assessment["severity"].upper()
    score = risk_assessment["score"]
    verdict = risk_assessment["verdict"]

    # Color tokens based on threat severity
    color_map = {
        "CRITICAL": {"badge": "#dc3545", "bg": "#f8d7da", "text": "#721c24"},
        "HIGH":     {"badge": "#fd7e14", "bg": "#fff3cd", "text": "#856404"},
        "MEDIUM":   {"badge": "#ffc107", "bg": "#fff3cd", "text": "#856404"},
        "LOW":      {"badge": "#28a745", "bg": "#d4edda", "text": "#155724"}
    }
    colors = color_map.get(severity, color_map["LOW"])

    # Build Header Anomaly Table Rows
    header_rows = ""
    for item in results.get("header_anomalies", []):
        header_rows += f"<tr><td>{item['reason']}</td><td><span class='score'>+{item['risk_score']} pts</span></td></tr>"

    # Build Quishing Table Rows
    qr_rows = ""
    for item in results.get("qr_analysis", []):
        indicators = ", ".join(item.get("indicators", []))
        qr_rows += f"""
        <tr>
            <td><code>{item['source_image']}</code></td>
            <td><a href='#' style='color:#0d6efd;'>{item['qr_url']}</a></td>
            <td>{indicators}</td>
            <td><span class='score'>+{item['risk_score']} pts</span></td>
        </tr>
        """

    # Build Attachment Table Rows
    attachment_rows = ""
    for att in results.get("attachment_analysis", []):
        reasons = ", ".join(att.get("reasons", []))
        attachment_rows += f"""
        <tr>
            <td><code>{att['filename']}</code></td>
            <td><code>{att['sha256']}</code></td>
            <td>{reasons}</td>
            <td><span class='score'>+{att['risk_score']} pts</span></td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Phishing Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f9; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 900px; margin: auto; background: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 30px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 15px; margin-bottom: 25px; }}
        .title {{ font-size: 22px; font-weight: bold; margin: 0; }}
        .timestamp {{ font-size: 13px; color: #6c757d; }}
        .summary-card {{ background: {colors['bg']}; border-left: 6px solid {colors['badge']}; color: {colors['text']}; padding: 20px; border-radius: 4px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; }}
        .badge {{ background: {colors['badge']}; color: #fff; padding: 6px 12px; border-radius: 4px; font-size: 14px; font-weight: bold; text-transform: uppercase; }}
        .score-box {{ text-align: right; }}
        .score-val {{ font-size: 28px; font-weight: bold; margin: 0; }}
        h3 {{ border-bottom: 1px solid #ddd; padding-bottom: 6px; margin-top: 25px; color: #212529; font-size: 16px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #e9ecef; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        code {{ background: #f1f3f5; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 13px; }}
        .score {{ color: #dc3545; font-weight: bold; }}
        .empty {{ font-style: italic; color: #888; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 class="title">Phishing Incident Triage Report</h1>
                <div class="timestamp">Generated at {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
            </div>
            <div class="badge">{severity}</div>
        </div>

        <div class="summary-card">
            <div>
                <h2 style="margin: 0; font-size: 20px;">Verdict: {verdict}</h2>
                <p style="margin: 5px 0 0 0; font-size: 14px;">Categories Flagged: <strong>{', '.join(results.get('categories', ['None']))}</strong></p>
            </div>
            <div class="score-box">
                <div class="score-val">{score}</div>
                <div style="font-size: 12px; text-transform: uppercase;">Total Risk Score</div>
            </div>
        </div>

        <h3>Header & Sender Anomalies</h3>
        {f"<table><thead><tr><th>Indicator / Anomaly</th><th>Risk</th></tr></thead><tbody>{header_rows}</tbody></table>" if header_rows else "<p class='empty'>No header anomalies detected.</p>"}

        <h3>Quishing / Decoded QR Artifacts</h3>
        {f"<table><thead><tr><th>Source</th><th>Decoded Destination URL</th><th>Flags</th><th>Risk</th></tr></thead><tbody>{qr_rows}</tbody></table>" if qr_rows else "<p class='empty'>No embedded QR codes detected.</p>"}

        <h3>Attachment Payloads</h3>
        {f"<table><thead><tr><th>Filename</th><th>SHA-256 Hash</th><th>Indicators</th><th>Risk</th></tr></thead><tbody>{attachment_rows}</tbody></table>" if attachment_rows else "<p class='empty'>No suspicious attachments analyzed.</p>"}
    </div>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] Human-friendly HTML report generated at '{output_file}'")
    return output_file

# ==========================================
# PARSING & EXTRACTION
# ==========================================
def extract_urls(message):
    """Locate and sanitize plaintext URLs found within the message body."""
    url_pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(url_pattern, message)

    cleaned_urls = []
    for url in urls:
        url = url.rstrip(".,);!?")
        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


class EmailHTMLLinkParser(HTMLParser):
    """HTML parser designed to extract hyperlink URLs (href) alongside their associated visible display text."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.current_href = None
        self.current_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            attributes = dict(attrs)
            self.current_href = attributes.get("href")
            self.current_text = []

    def handle_data(self, data):
        if self.current_href is not None:
            self.current_text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.current_href is not None:
            visible_text = "".join(self.current_text).strip()
            self.links.append(
                {
                    "href": self.current_href,
                    "visible_text": visible_text,
                }
            )
            self.current_href = None
            self.current_text = []


def extract_html_links(html_message):
    """Safely parse HTML content and extract all hyperlink dictionaries."""
    parser = EmailHTMLLinkParser()
    try:
        parser.feed(html_message)
        parser.close()
    except Exception:
        return []
    return parser.links


# ==========================================
# CORE ANALYSIS & RISK SCORING FUNCTIONS
# ==========================================
def analyze_html_link(link):
    """Compare a displayed URL with the actual hyperlink destination."""
    href = link["href"]
    visible_text = link["visible_text"].strip()

    actual_hostname = extract_hostname(href)
    displayed_hostname = None
    display_url_mismatch = False

    if visible_text.lower().startswith(("http://", "https://", "www.")):
        text_to_parse = visible_text
        if visible_text.lower().startswith("www."):
            text_to_parse = "http://" + visible_text
        displayed_hostname = extract_hostname(text_to_parse)

    if (
        actual_hostname
        and displayed_hostname
        and actual_hostname.lower() != displayed_hostname.lower()
    ):
        display_url_mismatch = True

    return {
        "href": href,
        "visible_text": visible_text,
        "actual_hostname": actual_hostname,
        "displayed_hostname": displayed_hostname,
        "display_url_mismatch": display_url_mismatch,
    }


def analyze_url(url):
    """Analyze a URL for suspicious structural indicators and typosquatting."""
    hostname = extract_hostname(url)
    indicators = []
    parsed = urlparse(url)

    if parsed.scheme.lower() == "http":
        indicators.append("uses_http")

    if is_ip_address(hostname):
        indicators.append("ip_address_hostname")

    if "@" in url:
        indicators.append("contains_at_symbol")

    if hostname and not is_ip_address(hostname) and hostname.count(".") >= 3:
        indicators.append("many_subdomains")

    matched_words = []
    lower_url = url.lower()
    for word in SUSPICIOUS_URL_WORDS:
        pattern = r"\b" + re.escape(word) + r"\b"
        if re.search(pattern, lower_url):
            matched_words.append(word)

    if matched_words:
        indicators.append("suspicious_url_words")

    typo_analysis = detect_brand_typosquatting(hostname)
    if typo_analysis:
        indicators.append("brand_typosquatting")

    return {
        "url": url,
        "hostname": hostname,
        "indicators": indicators,
        "matched_words": matched_words,
        "typo_analysis": typo_analysis,
        "suspicious": len(indicators) > 0,
    }


def calculate_unified_risk(url_analysis, display_mismatch=False):
    """Calculate a single, unified risk score combining structural URL rules and HTML mismatch indicators."""
    score = 0

    indicator_weights = {
        "uses_http": 15,
        "ip_address_hostname": 30,
        "contains_at_symbol": 25,
        "many_subdomains": 15,
        "suspicious_url_words": 10,
        "display_url_mismatch": 35,
        "brand_typosquatting": 35,
    }

    for indicator in url_analysis["indicators"]:
        score += indicator_weights.get(indicator, 0)

    if display_mismatch:
        score += indicator_weights["display_url_mismatch"]

    if score >= 50:
        severity = "high"
    elif score >= 25:
        severity = "medium"
    else:
        severity = "low"

    return {
        "url": url_analysis["url"],
        "score": score,
        "severity": severity,
    }


def calculate_phishing_risk(results):
    """Calculate an overall phishing risk score combining content, links, headers, attachments, and QR codes."""
    score = 0

    category_weights = {
        "urgency": 10,
        "threat": 20,
        "credential": 20,
        "money": 15,
        "reward": 15,
    }

    for category in results["categories"]:
        score += category_weights.get(category, 0)

    for link in results["link_analysis"]:
        score += link["risk_score"]

    for anomaly in results.get("header_anomalies", []):
        score += anomaly.get("risk_score", 0)

    for attachment in results.get("attachment_analysis", []):
        score += attachment.get("risk_score", 0)

    # QR Code quishing risks
    for qr in results.get("qr_analysis", []):
        score += qr.get("risk_score", 0)

    if score >= 100:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"

    if score >= 60:
        verdict = "Likely phishing"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Low risk"

    return {
        "score": score,
        "severity": severity,
        "verdict": verdict,
    }


def analyze_message(message, raw_mime_string=None):
    """Evaluate message text, raw URLs, HTML links, headers, attachments, and QR codes in a unified pipeline."""
    normalized_message = normalize_message(message)

    # 1. Header & Brand Protection Analysis
    header_anomalies = []
    parsed_headers = {}

    if raw_mime_string:
        parsed_headers = parse_email_headers(raw_mime_string)

        spoof_check = detect_display_name_spoofing(parsed_headers["from"])
        if spoof_check:
            header_anomalies.append(spoof_check)

        dmarc_check = check_tech_giant_dmarc(
            parsed_headers["sender_domain"], parsed_headers["auth_results"]
        )
        if dmarc_check:
            header_anomalies.append(dmarc_check)

        if parsed_headers["reply_to"] and parsed_headers["sender_domain"] not in parsed_headers["reply_to"]:
            header_anomalies.append({
                "reason": f"Reply-To address '{parsed_headers['reply_to']}' does not match sender domain '{parsed_headers['sender_domain']}'",
                "risk_score": 20
            })

    # 2. Attachment Analysis
    attachment_analysis = []
    if raw_mime_string:
        attachment_analysis = analyze_attachments(raw_mime_string)

    # 3. QR Code (Quishing) Analysis
    qr_analysis = []
    if raw_mime_string:
        qr_analysis = analyze_email_qr_codes(raw_mime_string)

    # 4. Text Category Analysis
    detected_categories = []
    matched_indicators = {}

    for category, keywords in PHISHING_KEYWORDS.items():
        matches = detect_keywords(normalized_message, keywords)
        if matches:
            detected_categories.append(category)
            matched_indicators[category] = matches

    # 5. HTML Link Analysis
    html_links = extract_html_links(message)
    evaluated_links = []

    for link in html_links:
        link_info = analyze_html_link(link)
        url_info = analyze_url(link_info["href"])
        risk = calculate_unified_risk(
            url_info, display_mismatch=link_info["display_url_mismatch"]
        )

        evaluated_links.append(
            {
                "href": link_info["href"],
                "visible_text": link_info["visible_text"],
                "displayed_hostname": link_info["displayed_hostname"],
                "actual_hostname": link_info["actual_hostname"],
                "display_url_mismatch": link_info["display_url_mismatch"],
                "indicators": url_info["indicators"],
                "risk_score": risk["score"],
                "severity": risk["severity"],
            }
        )

    suspicious_url_count = sum(
        1 for link in evaluated_links if link["severity"] in ("medium", "high")
    )

    suspicious_attachments_count = sum(
        1 for att in attachment_analysis if att["suspicious"]
    )

    return {
        "detected": (
            len(detected_categories) > 0
            or suspicious_url_count > 0
            or len(header_anomalies) > 0
            or suspicious_attachments_count > 0
            or len(qr_analysis) > 0
        ),
        "categories": detected_categories,
        "category_count": len(detected_categories),
        "matched_indicators": matched_indicators,
        "link_analysis": evaluated_links,
        "suspicious_url_count": suspicious_url_count,
        "header_info": parsed_headers,
        "header_anomalies": header_anomalies,
        "attachment_analysis": attachment_analysis,
        "suspicious_attachments_count": suspicious_attachments_count,
        "qr_analysis": qr_analysis,
    }


# ==========================================
# SCRIPT EXECUTION & TEST SUITE
# ==========================================
# ==========================================
# SCRIPT EXECUTION & TEST SUITE
# ==========================================
if __name__ == "__main__":
    import io
    import qrcode
    from email.message import EmailMessage

    # 1. Generate sample QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data("https://microsoft-login-update.com/mfa-verify")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="PNG")
    qr_image_bytes = img_byte_arr.getvalue()

    # 2. Build MIME message
    msg = EmailMessage()
    msg["From"] = '"Microsoft Security" <update@fake-security-update.com>'
    msg["To"] = "user@example.com"
    msg["Subject"] = "Urgent Security Action Required"
    msg.set_content(
        "Please scan the attached QR code immediately to verify your password and credentials."
    )
    
    msg.add_attachment(
        qr_image_bytes,
        maintype="image",
        subtype="png",
        filename="security_qr.png",
    )

    raw_mime_email = msg.as_string()

    print("Running Phishing Engine Analysis (Phase 9 - SIEM & Analyst Reporting)...")
    print("=" * 60)

    # 3. Execute analysis
    results = analyze_message(
        "Please scan the attached QR code immediately to verify your password and credentials.",
        raw_mime_string=raw_mime_email,
    )
    phishing_risk = calculate_phishing_risk(results)

    # 4. Phase 9 Outputs
    print("\n[+] Generating Phase 9 Outputs...")
    export_json_log(results, phishing_risk, output_file="phishing_events.json")
    generate_analyst_report(results, phishing_risk, output_file="analyst_report.html")

    print("\n" + "=" * 30)
    print("FINAL PHISHING RISK ASSESSMENT")
    print("=" * 30)
    print(f"Total Risk Score : {phishing_risk['score']}")
    print(f"Risk Severity    : {phishing_risk['severity'].upper()}")
    print(f"Final Verdict    : {phishing_risk['verdict']}")