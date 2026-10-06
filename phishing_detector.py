# ==========================================
# IMPORTS
# Standard library dependencies
# ==========================================
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
    """Analyze a URL for suspicious structural indicators."""
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

    return {
        "url": url,
        "hostname": hostname,
        "indicators": indicators,
        "matched_words": matched_words,
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


def analyze_message(message):
    """Evaluate message text, raw URLs, and HTML links in a unified analysis pipeline."""
    normalized_message = normalize_message(message)

    # 1. Text category analysis
    detected_categories = []
    matched_indicators = {}

    for category, keywords in PHISHING_KEYWORDS.items():
        matches = detect_keywords(normalized_message, keywords)
        if matches:
            detected_categories.append(category)
            matched_indicators[category] = matches

    # 2. HTML Link analysis (Evaluates structural URL risk + Display mismatch risk)
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

    return {
        "detected": len(detected_categories) > 0 or suspicious_url_count > 0,
        "categories": detected_categories,
        "category_count": len(detected_categories),
        "matched_indicators": matched_indicators,
        "link_analysis": evaluated_links,
        "suspicious_url_count": suspicious_url_count,
    }


# ==========================================
# SCRIPT EXECUTION
# Main entry point and sample run
# ==========================================
if __name__ == "__main__":
    sample_email = """
    <html>
    <body>

    <p>Dear customer,</p>

    <p>
    Please review your statement at:
    <a href="https://example.com/document">
    View document
    </a>
    </p>

    <p>
    Urgent: Update your credentials immediately at:
    <a href="http://192.0.2.55/login">
    https://paypal.com/login
    </a>
    </p>

    </body>
    </html>
    """

    print("Running Phishing Detection Analysis...\n" + "=" * 40)

    results = analyze_message(sample_email)

    print(f"Overall Suspicious Flag: {results['detected']}")
    print(
        f"Detected Keyword Categories ({results['category_count']}): {results['categories']}"
    )

    print("\nMatched Text Indicators:")
    for category, indicators in results["matched_indicators"].items():
        print(f" - {category}: {', '.join(indicators)}")

    print(f"\nLink Risk Analysis ({results['suspicious_url_count']} flagged):")
    for link in results["link_analysis"]:
        print(f"\n Destination : {link['href']}")
        print(f" Display Text: {link['visible_text']}")
        print(f" Mismatch    : {link['display_url_mismatch']}")
        print(f" Indicators  : {link['indicators']}")
        print(f" Risk Score  : {link['risk_score']}")
        print(f" Severity    : {link['severity'].upper()}")