message = """
Your password expires today.
Click here immediately to reset it.
"""

message = message.lower()

total_clues = 0

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
        total_clues += 1

for word in threat_words:
    if word in message:
        print("⚠️ Threat detected:", word)
        total_clues += 1

for word in credential_words:
    if word in message:
        print("⚠️ Credential request detected:", word)
        total_clues += 1

for word in money_words:
    if word in message:
        print("⚠️ Money-related language detected:", word)
        total_clues += 1

for word in reward_words:
    if word in message:
        print("⚠️ Reward/scam language detected:", word)
        total_clues += 1

print("\nTotal suspicious clues:", total_clues)