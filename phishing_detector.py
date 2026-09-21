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


def normalize_message(message):
    return message.lower().strip()


def detect_keywords(message, keywords):
    matches = []

    for keyword in keywords:
        if keyword in message:
            matches.append(keyword)

    return matches


def analyze_message(message):
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


if __name__ == "__main__":
    message = """
Congratulations! You are the winner of a free phone.
Claim your prize immediately or your reward will expire today.
"""

    result = analyze_message(message)

    print("Checking message...\n")

    print("Suspicious:", result["detected"])
    print("Detected categories:", result["categories"])
    print("Number of suspicious categories:", result["category_count"])

    print("\nMatched indicators:")

    for category, indicators in result["matched_indicators"].items():
        print(f"- {category}: {', '.join(indicators)}")