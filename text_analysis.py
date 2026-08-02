"""
text_analysis.py
-----------------
Rule-based phishing text analyzer for PhishGuard.

This module does NOT use AI/ML. It uses simple keyword matching and
weighted scoring to estimate how "phishing-like" a piece of text is.

Main entry point: analyze_text(text) -> dict
"""

import re
from url_analysis import find_urls_in_text, analyze_url

# ---------------------------------------------------------------------------
# CONFIGURABLE PHISHING INDICATOR DICTIONARY
# ---------------------------------------------------------------------------
# Each category has:
#   - keywords: list of words/phrases to search for (case-insensitive)
#   - weight: points added to the danger score if ANY keyword in the
#             category is found (weight is added only once per category)
#   - label: human-readable name shown in the threat report
#
# Feel free to add/remove keywords or tweak weights — this dictionary is
# the "brain" of the rule-based detector.
# ---------------------------------------------------------------------------

PHISHING_INDICATORS = {
    "urgent_language": {
        "label": "Urgent / Pressure Language",
        "weight": 10,
        "keywords": [
            "urgent", "immediately", "act now", "limited time", "verify now",
            "act fast", "final notice", "last warning", "expire", "expires",
            "expiring", "right away", "within 24 hours", "time sensitive",
            "respond immediately", "asap",
        ],
    },
    "otp_request": {
        "label": "OTP / One-Time-Password Request",
        "weight": 15,
        "keywords": [
            "otp", "one time password", "one-time password", "verification code",
            "security code", "authentication code",
        ],
    },
    "password_request": {
        "label": "Password Request",
        "weight": 20,
        "keywords": [
            "enter your password", "confirm your password", "update your password",
            "password expired", "reset your password", "share your password",
            "provide your password",
        ],
    },
    "pin_request": {
        "label": "PIN Request",
        "weight": 20,
        "keywords": [
            "enter your pin", "confirm your pin", "share your pin", "pin number",
            "atm pin", "card pin",
        ],
    },
    "banking_keywords": {
        "label": "Banking / Financial Institution Keywords",
        "weight": 10,
        "keywords": [
            "bank account", "account blocked", "account suspended", "account locked",
            "account has been blocked", "account has been suspended", "debit card",
            "credit card", "net banking", "internet banking", "ifsc", "swift code",
            "wire transfer", "bank statement",
        ],
    },
    "prize_scam": {
        "label": "Prize / Lottery Scam",
        "weight": 15,
        "keywords": [
            "you have won", "you've won", "congratulations you", "lucky winner",
            "lottery", "prize money", "claim your prize", "reward points expiring",
            "selected winner", "jackpot",
        ],
    },
    "gift_card_scam": {
        "label": "Gift Card Scam",
        "weight": 15,
        "keywords": [
            "gift card", "itunes card", "amazon gift card", "google play card",
            "steam card", "redeem code",
        ],
    },
    "account_blocked": {
        "label": "Account Blocked / Suspended Alert",
        "weight": 15,
        "keywords": [
            "account blocked", "account suspended", "account disabled",
            "account restricted", "account deactivated", "unusual activity detected",
        ],
    },
    "security_alert": {
        "label": "Fake Security Alert",
        "weight": 10,
        "keywords": [
            "security alert", "unauthorized login", "suspicious login",
            "unusual sign-in activity", "security breach", "your account was accessed",
        ],
    },
    "login_request": {
        "label": "Login Request",
        "weight": 10,
        "keywords": [
            "login to verify", "log in to confirm", "sign in to verify",
            "login here", "click to login", "re-login",
        ],
    },
    "verification_request": {
        "label": "Verification Request",
        "weight": 10,
        "keywords": [
            "verify your account", "verify your identity", "confirm your identity",
            "verify your details", "verify now", "confirm your account",
            "kyc update", "update your kyc",
        ],
    },
    "financial_request": {
        "label": "Financial / Payment Request",
        "weight": 10,
        "keywords": [
            "make a payment", "pending payment", "invoice attached", "outstanding balance",
            "pay now", "refund pending", "processing fee", "release your parcel",
            "customs fee",
        ],
    },
    "crypto_scam": {
        "label": "Cryptocurrency Scam",
        "weight": 15,
        "keywords": [
            "bitcoin", "cryptocurrency", "crypto wallet", "usdt", "ethereum",
            "double your investment", "crypto investment", "wallet seed phrase",
            "send bitcoin",
        ],
    },
    "fake_support_scam": {
        "label": "Fake Tech / Customer Support Scam",
        "weight": 10,
        "keywords": [
            "call this number immediately", "tech support", "customer care executive",
            "your computer is infected", "remote access", "anydesk", "teamviewer",
        ],
    },
    "personal_info_request": {
        "label": "Personal Information Request",
        "weight": 15,
        "keywords": [
            "social security number", "aadhaar number", "passport number",
            "date of birth", "mother's maiden name", "full name and address",
            "provide your details",
        ],
    },
    "phone_action_request": {
        "label": "Phone Number Requesting Action",
        "weight": 5,
        "keywords": [
            "call this number", "contact us at", "sms your", "whatsapp us at",
        ],
    },
}

# Weight added if one or more email addresses are found inside the text
EMAIL_PRESENCE_WEIGHT = 5
# Weight added per suspicious URL detected inside the pasted text (see url_analysis.py)
URL_IN_TEXT_MAX_WEIGHT = 20

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def _find_keyword_hits(text_lower, keywords):
    """Return list of keywords found in text_lower (case-insensitive substring match)."""
    hits = []
    for kw in keywords:
        if kw.lower() in text_lower:
            hits.append(kw)
    return hits


def analyze_text(raw_text):
    """
    Analyze a block of text for phishing indicators.

    Args:
        raw_text (str): the message text to analyze (from paste box or OCR output)

    Returns:
        dict with keys:
            danger_score (int 0-100)
            risk_level (str)
            detected_indicators (list of str) - human-readable labels
            matched_keywords (dict) - category -> list of matched keywords
            urls_found (list of dict) - result of analyze_url() for each URL found
            emails_found (list of str)
            error (str or None)
    """
    result = {
        "danger_score": 0,
        "risk_level": "Safe",
        "detected_indicators": [],
        "matched_keywords": {},
        "urls_found": [],
        "emails_found": [],
        "error": None,
    }

    if raw_text is None or not raw_text.strip():
        result["error"] = "No text was provided for analysis. Please paste a message or upload a screenshot with readable text."
        return result

    text = raw_text.strip()
    text_lower = text.lower()

    score = 0
    detected_indicators = []
    matched_keywords = {}

    # 1. Keyword-category scan
    for category_key, category in PHISHING_INDICATORS.items():
        hits = _find_keyword_hits(text_lower, category["keywords"])
        if hits:
            score += category["weight"]
            detected_indicators.append(category["label"])
            matched_keywords[category["label"]] = hits

    # 2. Email address detection
    emails_found = EMAIL_REGEX.findall(text)
    if emails_found:
        score += EMAIL_PRESENCE_WEIGHT
        detected_indicators.append("Email Address Present")
        result["emails_found"] = emails_found

    # 3. URL detection inside text (delegate scoring to url_analysis module)
    urls = find_urls_in_text(text)
    url_results = []
    if urls:
        highest_url_score = 0
        for u in urls:
            url_result = analyze_url(u)
            url_results.append(url_result)
            highest_url_score = max(highest_url_score, url_result["danger_score"])

        # Add a capped contribution from the worst URL found, so text + URL
        # scoring doesn't runaway past 100 too easily.
        url_contribution = min(URL_IN_TEXT_MAX_WEIGHT, round(highest_url_score * 0.3))
        score += url_contribution
        detected_indicators.append("Suspicious URL Found in Message")
        result["urls_found"] = url_results

    # Cap score at 100
    score = min(100, score)

    result["danger_score"] = score
    result["risk_level"] = get_risk_level(score)
    result["detected_indicators"] = detected_indicators
    result["matched_keywords"] = matched_keywords

    return result


def get_risk_level(score):
    """Map a 0-100 danger score to a risk level label."""
    if score <= 25:
        return "Safe"
    elif score <= 50:
        return "Low Risk"
    elif score <= 75:
        return "Medium Risk"
    else:
        return "High Risk"


def get_recommendations(detected_indicators):
    """
    Generate a dynamic list of safety recommendations based on
    which indicators were detected.
    """
    recs = set()

    mapping = {
        "OTP / One-Time-Password Request": "Never share an OTP with anyone, even if they claim to be your bank.",
        "Password Request": "Never share your password. Legitimate companies will never ask for it.",
        "PIN Request": "Never share your PIN with anyone over message, call, or email.",
        "Banking / Financial Institution Keywords": "Contact your bank directly using the number on your card, not the message.",
        "Prize / Lottery Scam": "Be skeptical of unexpected prizes — legitimate lotteries don't require upfront payment.",
        "Gift Card Scam": "No legitimate organization asks for payment via gift cards.",
        "Account Blocked / Suspended Alert": "Log in only through the official app or website, not a link in the message.",
        "Fake Security Alert": "Verify security alerts directly through the official app, not via links provided.",
        "Login Request": "Do not click login links from messages — type the official website URL yourself.",
        "Verification Request": "Verify your identity only on official websites you navigate to directly.",
        "Financial / Payment Request": "Confirm payment requests through official channels before paying.",
        "Cryptocurrency Scam": "Be cautious of guaranteed investment returns — this is a common scam pattern.",
        "Fake Tech / Customer Support Scam": "Never grant remote access to your device based on an unsolicited message.",
        "Personal Information Request": "Avoid sharing personal identification details over text or email.",
        "Phone Number Requesting Action": "Verify unknown phone numbers independently before calling or texting back.",
        "Urgent / Pressure Language": "Be cautious of messages that create urgency — this is a common manipulation tactic.",
        "Email Address Present": "Check that the sender's email domain matches the official organization's domain.",
        "Suspicious URL Found in Message": "Do not click suspicious links. Type the official website address directly into your browser.",
    }

    for indicator in detected_indicators:
        if indicator in mapping:
            recs.add(mapping[indicator])

    # Always include general baseline advice
    recs.add("Enable Two-Factor Authentication (2FA) on your important accounts.")
    recs.add("When in doubt, delete the suspicious message or report it.")

    return sorted(recs)