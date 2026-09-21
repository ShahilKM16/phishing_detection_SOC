message = """
Congratulations! You are the winner of a free phone.
Claim your prize immediately or your reward will expire today.
"""

message = message.lower()

detected_categories = []

urgency_words = [
    "urgent",
    "immediately",
    "action required",
    "act now",
    "expires today",
    "within 24 hours"
]

threat_words = [
    "suspended",
    "locked",
    "disabled",
    "terminated",
    "legal action",
    "account closure"
]

credential_words = [
    "password",
    "login",
    "sign in",
    "verify your account",
    "confirm your identity",
    "security verification"
]

money_words = [
    "payment",
    "invoice",
    "refund",
    "tax",
    "wire transfer",
    "bank account",
    "direct deposit"
]

reward_words = [
    "you won",
    "winner",
    "prize",
    "reward",
    "free",
    "cash prize",
    "gift card"
]

print("Checking message...\n")

for word in urgency_words:
    if word in message:
        print("⚠️ Urgency detected:", word)

        if "urgency" not in detected_categories:
            detected_categories.append("urgency")

for word in threat_words:
    if word in message:
        print("⚠️ Threat detected:", word)

        if "threat" not in detected_categories:
            detected_categories.append("threat")
        

for word in credential_words:
    if word in message:
        print("⚠️ Credential request detected:", word)

        if "credential" not in detected_categories:
            detected_categories.append("credential")
        

for word in money_words:
    if word in message:
        print("⚠️ Money-related language detected:", word)

        if "money" not in detected_categories:
            detected_categories.append("money")
        

for word in reward_words:
    if word in message:
        print("⚠️ Reward/scam language detected:", word)

        if "reward" not in detected_categories:
            detected_categories.append("reward")
        

print("\nDetected categories:", detected_categories)
print("Number of suspicious categories:", len(detected_categories))