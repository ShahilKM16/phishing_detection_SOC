from phishing_detector import analyze_message, analyze_url, extract_urls

url_test_messages = [
    {
        "name": "HTTP IP phishing URL",
        "message": """
        Verify your account immediately:

        http://192.0.2.55/verify/account
        """,
    },

    {
        "name": "Suspicious login URL",
        "message": """
        Please access the portal:

        https://example.com/login/verification
        """,
    },

    {
        "name": "Normal documentation URL",
        "message": """
        Python documentation:

        https://docs.python.org/
        """,
    },

    {
        "name": "No URL",
        "message": """
        Hi team,

        Today's project meeting starts at 2 PM.
        """,
    },
]


for test in url_test_messages:
    print("=" * 60)
    print("URL TEST:", test["name"])

    result = analyze_message(test["message"])

    print("URLs found:", result["urls_found"])
    print("Suspicious URLs:", result["suspicious_url_count"])

    for url_result in result["url_analysis"]:
        print("URL:", url_result["url"])
        print("Hostname:", url_result["hostname"])
        print("Indicators:", url_result["indicators"])