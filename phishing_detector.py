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
    """Scan normalized text against a list of keyword patterns."""
    matches = []

    for keyword in keywords:
        if keyword in message:
            matches.append(keyword)

    return matches


# ==========================================
# CORE ANALYSIS FUNCTIONS
# Message scanning and URL extraction logic
# ==========================================
def analyze_message(message):
    """Evaluate message text against categorized phishing indicators."""
    normalized_message = normalize_message(message)

    detected_categories = []
    matched_indicators = {}

    for category, keywords in PHISHING_KEYWORDS.items():
        matches = detect_keywords(normalized_message, keywords)

        if matches:
            detected_categories.append(category)
            matched_indicators[category] = matches

    return {
        "detected": len(detected_categories) > 0,
        "categories": detected_categories,
        "category_count": len(detected_categories),
        "matched_indicators": matched_indicators,
    }


def extract_urls(message):
    """Locate and sanitize URLs found within the message body."""
    url_pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(url_pattern, message)

    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,);!?")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


class EmailHTMLLinkParser(HTMLParser):
    """HTML parser designed to extract hyperlink URLs (href) alongside their associated visible display text from raw email bodies."""

    def __init__(self):
        super().__init__()

        # Stores extracted link objects: [{'href': ..., 'visible_text': ...}]
        self.links = []

        # State tracking variables for the tag currently being processed
        self.current_href = None
        self.current_text = []

    def handle_starttag(self, tag, attrs):
        """Triggered when an opening HTML tag is encountered."""
        if tag == "a":
            # Convert attributes list of tuples [('href', '...'), ...] into a dictionary
            attributes = dict(attrs)

            # Capture destination URL and reset text accumulator for this tag
            self.current_href = attributes.get("href")
            self.current_text = []

    def handle_data(self, data):
        """Triggered when inner text content between tags is encountered."""
        # Only accumulate text if we are actively inside an anchor (<a>) tag
        if self.current_href is not None:
            self.current_text.append(data)

    def handle_endtag(self, tag):
        """Triggered when a closing HTML tag is encountered."""
        if tag == "a" and self.current_href is not None:
            # Combine non-contiguous text chunks (e.g., inner tags or spaces) into a single string
            visible_text = "".join(self.current_text).strip()

            # Record the completed link object
            self.links.append(
                {
                    "href": self.current_href,
                    "visible_text": visible_text,
                }
            )

            # Reset tracking state for the next anchor tag
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


def extract_hostname(url):
    """Extract the hostname from a URL."""

    parsed = urlparse(url)

    return parsed.hostname


def analyze_html_link(link):
    """Compare a displayed URL with the actual hyperlink destination."""
    
    href = link["href"]
    visible_text = link["visible_text"].strip()

    actual_hostname = extract_hostname(href)

    displayed_hostname = None
    display_url_mismatch = False

    if visible_text.lower().startswith(("http://", "https://")):
        displayed_hostname = extract_hostname(visible_text)

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


# ==========================================
# SCRIPT EXECUTION
# Main entry point and sample run
# ==========================================
if __name__ == "__main__":
    message = """
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
    <a href= "http://192.0.2.55/login">
    https://paypal.com/login
    </a>
    </p>

    </body>
    </html>
    """

    print("Extracted URLs:", extract_urls(message))
    print("HTML Links:", extract_html_links(message))

    print("\nHTML Link Analysis:")

    for link in extract_html_links(message):
        link_analysis = analyze_html_link(link)

        print("\nVisible text:", link_analysis["visible_text"])
        print("Actual destination:", link_analysis["href"])
        print("Displayed hostname:", link_analysis["displayed_hostname"])
        print("Actual hostname:", link_analysis["actual_hostname"])
        print("URL mismatch:", link_analysis["display_url_mismatch"])

    print("\nHostnames:")

    for url in extract_urls(message):
        print(f"- {url} -> {extract_hostname(url)}")

    print("\nChecking message...\n")

    result = analyze_message(message)

    print("Suspicious:", result["detected"])
    print("Detected categories:", result["categories"])
    print("Number of suspicious categories:", 
          result["category_count"])

    print("\nMatched indicators:")

    for category, indicators in result["matched_indicators"].items():
        print(f"- {category}: {', '.join(indicators)}")