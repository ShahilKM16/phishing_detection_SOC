# ==========================================
# IMPORTS
# Standard library dependencies
# ==========================================
import email
import hashlib
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

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

# High-value tech giant targets for brand protection
PROTECTED_BRANDS = {
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "linkedin": "linkedin.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
}

# Dangerous attachment file extensions often used in malware delivery
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
# Text transformation and basic matching
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

    # Extract sender domain from "From" header
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

        # Brand string embedded in unofficial domain (e.g., paypal-security.com)
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

        # Identify attachments via Content-Disposition header or explicit filename
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

            # 1. Check dangerous extension
            has_dangerous_extension = any(
                lower_filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS
            )
            if has_dangerous_extension:
                indicators.append("dangerous_file_extension")
                risk_score += 40

            # 2. Check double extension trick (e.g., invoice.pdf.exe)
            filename_parts = lower_filename.split(".")
            if len(filename_parts) > 2:
                # Double extension check
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

    # Check link destination for brand typosquatting
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
    """Calculate an overall phishing risk score combining content, links, headers, and attachments."""
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

    # Header anomalies
    for anomaly in results.get("header_anomalies", []):
        score += anomaly.get("risk_score", 0)

    # Attachment risks
    for attachment in results.get("attachment_analysis", []):
        score += attachment.get("risk_score", 0)

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
    """Evaluate message text, raw URLs, HTML links, headers, and attachments in a unified pipeline."""
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

    # 3. Text Category Analysis
    detected_categories = []
    matched_indicators = {}

    for category, keywords in PHISHING_KEYWORDS.items():
        matches = detect_keywords(normalized_message, keywords)
        if matches:
            detected_categories.append(category)
            matched_indicators[category] = matches

    # 4. HTML Link Analysis
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
    }


# ==========================================
# SCRIPT EXECUTION & TEST SUITE
# ==========================================
if __name__ == "__main__":
    # Simulated full MIME multi-part email with malicious double-extension attachment
    sample_mime_email = """From: "Microsoft Security Support" <attacker@fake-security-update.com>
Reply-To: harvest@badactor.org
Subject: Urgent Security Action Required
Content-Type: multipart/mixed; boundary="BOUNDARY_STRING"
Authentication-Results: mx.google.com; dmarc=fail header.from=microsoft.com

--BOUNDARY_STRING
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Dear customer,</p>
<p>
Urgent: Update your Microsoft account credentials immediately to prevent account closure:
<a href="http://192.0.2.55/login">
https://login.microsoftonline.com
</a>
</p>
<p>
Verify billing details at our partner domain:
<a href="https://paypal-security-update.com/verify">
https://paypal.com/verify
</a>
</p>
<p>Please review the attached invoice update.</p>
</body>
</html>

--BOUNDARY_STRING
Content-Type: application/octet-stream; name="Invoice_Update_2026.pdf.exe"
Content-Disposition: attachment; filename="Invoice_Update_2026.pdf.exe"
Content-Transfer-Encoding: base64

TVpQAAEAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAgAAA4fug4AtAnNIbgAAACACAABL...

--BOUNDARY_STRING--
"""

    print("Running Phishing Engine Analysis (Phase 7 - Attachments)...")
    print("=" * 60)

    # Extract body from MIME message for text analysis
    msg = email.message_from_string(sample_mime_email)
    html_body = ""
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            html_body = part.get_payload(decode=True).decode("utf-8")

    results = analyze_message(html_body, raw_mime_string=sample_mime_email)
    phishing_risk = calculate_phishing_risk(results)

    print(f"Overall Suspicious Flag : {results['detected']}")
    print(f"Categories Detected     : {results['categories']}")

    if results["header_anomalies"]:
        print("\n[!] Header & Brand Impersonation Anomalies:")
        for anomaly in results["header_anomalies"]:
            print(f" - {anomaly['reason']} (+{anomaly['risk_score']} pts)")

    if results["attachment_analysis"]:
        print(f"\n[!] Attachment Analysis ({results['suspicious_attachments_count']} flagged):")
        for att in results["attachment_analysis"]:
            print(f" - Filename   : {att['filename']}")
            print(f"   SHA-256    : {att['sha256']}")
            print(f"   Indicators : {att['indicators']}")
            print(f"   Risk Score : {att['risk_score']}")

    print(f"\nLink Risk Analysis ({results['suspicious_url_count']} flagged):")
    for link in results["link_analysis"]:
        print(f"\n Destination : {link['href']}")
        print(f" Display Text: {link['visible_text']}")
        print(f" Mismatch    : {link['display_url_mismatch']}")
        print(f" Indicators  : {link['indicators']}")
        print(f" Risk Score  : {link['risk_score']}")
        print(f" Severity    : {link['severity'].upper()}")

    print("\n" + "=" * 30)
    print("FINAL PHISHING RISK ASSESSMENT")
    print("=" * 30)
    print(f"Total Risk Score : {phishing_risk['score']}")
    print(f"Risk Severity    : {phishing_risk['severity'].upper()}")
    print(f"Final Verdict    : {phishing_risk['verdict']}")