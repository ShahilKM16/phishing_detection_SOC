from phishing_detector import analyze_message

test_messages = [
    {
        "name": "Prize scam",
        "message": """
Congratulations! You are the winner of a free phone.
Claim your prize immediately.
""",
    },
    {
        "name": "Password expiry",
        "message": """
Your password expires today.
Sign in immediately to verify your account.
""",
    },
    {
        "name": "Fake invoice",
        "message": """
Your outstanding invoice requires immediate payment.
""",
    },
    {
        "name": "Legal threat",
        "message": """
Legal action will be initiated unless you respond immediately.
""",
    },
    {
        "name": "Normal email",
        "message": """
Hi Sarah,
The project meeting has moved to Wednesday afternoon.
Please let me know if you can attend.
Thanks.
""",
    },
]

for test in test_messages:
    print("=" * 60)
    print("TEST:", test["name"])

    result = analyze_message(test["message"])

    print("Suspicious:", result["detected"])
    print("Categories:", result["categories"])
    print("Indicators:", result["matched_indicators"])