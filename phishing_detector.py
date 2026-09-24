import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

# --- Constants ---
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


# --- Helper Functions ---
def normalize_message(message):
    return message.lower().strip()


def detect_keywords(message, keywords):
    matches = []
    for keyword in keywords:
        if keyword in message:
            matches.append(keyword)
    return matches


def extract_urls(message):
    url_pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(url_pattern, message)
    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,);!?")
        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def is_ip_address(hostname):
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


# --- Analysis Functions ---
def analyze_url(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    indicators = []

    if parsed_url.scheme.lower() == "http":
        indicators.append("uses_http")

    if is_ip_address(hostname):
        indicators.append("ip_address_hostname")

    if "@" in url:
        indicators.append("contains_at_symbol")

    if hostname.count(".") >= 3 and not is_ip_address(hostname):
        indicators.append("many_subdomains")

    lowercase_url = url.lower()
    suspicious_words_found = []

    for word in SUSPICIOUS_URL_WORDS:
        if word in lowercase_url:
            suspicious_words_found.append(word)

    if suspicious_words_found:
        indicators.append("suspicious_url_words")

    return {
        "url": url,
        "hostname": hostname,
        "scheme": parsed_url.scheme,
        "suspicious": len(indicators) > 0,
        "indicators": indicators,
        "suspicious_words": suspicious_words_found,
    }


def analyze_urls(message):
    urls = extract_urls(message)
    results = []

    for url in urls:
        result = analyze_url(url)
        results.append(result)

    return results


def analyze_message(message):
    normalized_message = normalize_message(message)

    detected_categories = []
    matched_indicators = {}

    for category, keywords in PHISHING_KEYWORDS.items():
        matches = detect_keywords(normalized_message, keywords)

        if matches:
            detected_categories.append(category)
            matched_indicators[category] = matches

    url_analysis = analyze_urls(message)

    suspicious_urls = [
        result for result in url_analysis if result["suspicious"]
    ]

    return {
        "detected": (
            len(detected_categories) > 0 or len(suspicious_urls) > 0
        ),
        "categories": detected_categories,
        "category_count": len(detected_categories),
        "matched_indicators": matched_indicators,
        "urls_found": len(url_analysis),
        "url_analysis": url_analysis,
        "suspicious_url_count": len(suspicious_urls),
    }


# --- Execution Block ---
if __name__ == "__main__":
    message = """
    Please visit:
    https://example.com/document
    Or:
    http://192.0.2.55/login
    """

    print("Checking message...\n")
    result = analyze_message(message)

    print("Suspicious:", result["detected"])
    print("Detected categories:", result["categories"])
    print("Number of suspicious categories:", result["category_count"])

    print("\nMatched indicators:")
    for category, indicators in result["matched_indicators"].items():
        print(f"- {category}: {', '.join(indicators)}")

    print("\nURL Analysis:")
    if result["urls_found"] == 0:
        print("No URLs found.")
    else:
        for url_result in result["url_analysis"]:
            print(f"\nURL: {url_result['url']}")
            print(f"Hostname: {url_result['hostname']}")
            print(f"Scheme: {url_result['scheme']}")
            print(f"Suspicious: {url_result['suspicious']}")
            print(f"Indicators: {url_result['indicators']}")
            print("Suspicious words:", url_result["suspicious_words"])