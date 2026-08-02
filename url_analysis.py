import re
from urllib.parse import urlparse
URL_REGEX = re.compile(
    r"(?:(?:https?://)|(?:www\.))[^\s<>\"']+", re.IGNORECASE
)

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "tiny.cc", "rb.gy",
    "shorturl.at", "bit.do",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click", ".loan", ".gq", ".tk",
    ".ml", ".ga", ".cf", ".info", ".biz", ".zip", ".mov", ".link",
]

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "banking", "webscr", "password", "credential", "authenticate", "unlock",
    "suspend", "billing", "support",
]

COMMON_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "instagram",
    "netflix", "bankofamerica", "chase", "wellsfargo", "hdfc", "icici", "sbi",
    "whatsapp", "outlook", "office365", "linkedin", "dropbox",
]

IP_ADDRESS_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def find_urls_in_text(text):
    """Find all URL-like substrings in a block of text."""
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    cleaned = [m.rstrip(").,;!?\"'") for m in matches]
    return cleaned


def _normalize_url(url):
    """Ensure the URL has a scheme so urlparse works correctly."""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return "http://" + url
    return url


def analyze_url(raw_url):
    """
    Analyze a single URL for phishing-like structural characteristics.

    Returns dict with:
        url (str) - original input
        danger_score (int 0-100)
        risk_level (str)
        detected_indicators (list of str)
        error (str or None)
    """
    result = {
        "url": raw_url,
        "danger_score": 0,
        "risk_level": "Safe",
        "detected_indicators": [],
        "error": None,
    }

    if not raw_url or not raw_url.strip():
        result["error"] = "No URL was provided. Please paste a website link to analyze."
        return result

    original_input = raw_url.strip()
    normalized = _normalize_url(original_input)

    try:
        parsed = urlparse(normalized)
    except Exception:
        result["error"] = "The provided text does not appear to be a valid URL."
        return result

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        result["error"] = "Could not detect a valid domain in the provided URL."
        return result

    score = 0
    indicators = []

    if parsed.scheme == "http":
        score += 10
        indicators.append("Uses insecure HTTP instead of HTTPS")

    if len(normalized) > 75:
        score += 10
        indicators.append("Unusually long URL")

    if IP_ADDRESS_REGEX.match(hostname):
        score += 20
        indicators.append("URL uses a raw IP address instead of a domain name")

    dot_count = hostname.count(".")
    if dot_count >= 3:
        score += 10
        indicators.append("Multiple subdomains detected")

    hyphen_count = hostname.count("-")
    if hyphen_count >= 2:
        score += 10
        indicators.append("Excessive hyphens in domain name")
    elif hyphen_count == 1:
        score += 5
        indicators.append("Hyphen present in domain name")

    digit_count = sum(c.isdigit() for c in hostname)
    if digit_count >= 3:
        score += 10
        indicators.append("Excessive numbers in domain name")

    for shortener in SHORTENER_DOMAINS:
        if shortener in hostname:
            score += 15
            indicators.append("Uses a URL shortening service (destination is hidden)")
            break

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            score += 15
            indicators.append(f"Uses a top-level domain often associated with spam ({tld})")
            break

    full_url_lower = normalized.lower()
    matched_words = [w for w in SUSPICIOUS_WORDS if w in full_url_lower]
    if matched_words:
        score += 15
        indicators.append(
            "Contains suspicious keywords: " + ", ".join(sorted(set(matched_words))[:5])
        )

    
    domain_parts = hostname.split(".")
    root_domain = domain_parts[-2] if len(domain_parts) >= 2 else hostname
    for brand in COMMON_BRANDS:
        if brand in hostname and root_domain != brand:
            score += 20
            indicators.append(
                f"Possible brand impersonation detected (contains '{brand}' but domain is not the official '{brand}.com')"
            )
            break

    if re.search(r"[@%]", normalized):
        score += 10
        indicators.append("Contains unusual special characters (@ or %)")

    score = min(100, score)

    result["danger_score"] = score
    result["risk_level"] = _get_risk_level(score)
    result["detected_indicators"] = indicators
    result["hostname"] = hostname

    return result


def _get_risk_level(score):
    if score <= 25:
        return "Safe"
    elif score <= 50:
        return "Low Risk"
    elif score <= 75:
        return "Medium Risk"
    else:
        return "High Risk"


def get_url_recommendations(detected_indicators):
    """Generate recommendations based on detected URL indicators."""
    recs = set()
    recs.add("Do not click suspicious links.")
    recs.add("Type the official website address directly into your browser instead of clicking links.")

    for indicator in detected_indicators:
        if "HTTP" in indicator:
            recs.add("Avoid entering any personal information on non-HTTPS websites.")
        if "IP address" in indicator:
            recs.add("Be very cautious of links that use a raw IP address instead of a domain name.")
        if "shortening" in indicator:
            recs.add("Expand shortened URLs using a trusted preview tool before clicking.")
        if "brand impersonation" in indicator:
            recs.add("Double-check the exact spelling of the domain against the official website.")
        if "top-level domain" in indicator:
            recs.add("Be cautious of unfamiliar domain extensions, especially on financial or login pages.")

    return sorted(recs)
