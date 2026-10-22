"""Offline, rule-based QR payload and URL risk analysis.

This module never visits a URL or sends a payload to an external service.
Its score is a learning aid, not a guarantee that a target is safe or malicious.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "ow.ly", "buff.ly", "lnkd.in", "soo.gd",
}

SUSPICIOUS_TERMS = {
    "login": "The link uses login-related wording.",
    "verify": "The link asks for verification, which can be used in credential phishing.",
    "account": "The link uses account-related wording.",
    "password": "The link mentions a password.",
    "wallet": "The link mentions a wallet or financial account.",
    "payment": "The link mentions payment.",
    "recover": "The link uses account-recovery wording.",
    "reset": "The link uses reset-related wording.",
    "confirm": "The link asks for confirmation.",
    "secure": "The word 'secure' appears in the address; this word alone does not prove legitimacy.",
}

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "netflix": "netflix.com",
}

SENSITIVE_QUERY_KEYS = {
    "password", "passwd", "token", "access_token", "refresh_token", "api_key",
    "apikey", "secret", "session", "sessionid", "auth", "authorization", "code",
}


def redact_sensitive_payload(payload: str) -> str:
    """Hide common secrets before showing, exporting, or saving payloads."""
    if not payload:
        return ""

    text = str(payload).strip()

    # Wi-Fi QR codes may contain the network password in a P: field.
    if text.upper().startswith("WIFI:"):
        text = re.sub(r"(?i)(;P:)([^;]*)", r"\1[REDACTED]", text)
        return text

    # Keep URL structure useful while masking commonly sensitive query values.
    try:
        parts = urlsplit(text)
        if parts.scheme.lower() in {"http", "https"} and parts.netloc:
            safe_query = []
            for key, value in parse_qsl(parts.query, keep_blank_values=True):
                if key.lower() in SENSITIVE_QUERY_KEYS or any(
                    word in key.lower() for word in ("password", "token", "secret", "apikey", "session")
                ):
                    safe_query.append((key, "[REDACTED]"))
                else:
                    safe_query.append((key, value))
            safe_netloc = parts.netloc
            # User-info embedded before @ can include credentials; hide it in every view/export.
            if "@" in safe_netloc:
                safe_netloc = "[REDACTED]@" + safe_netloc.rsplit("@", 1)[1]
            text = urlunsplit((parts.scheme, safe_netloc, parts.path, urlencode(safe_query), parts.fragment))
    except ValueError:
        pass

    # Also cover simple token-like key/value strings in plain-text QR payloads.
    text = re.sub(
        r"(?i)\b(password|passwd|token|access_token|refresh_token|api[_-]?key|secret|session(?:id)?|authorization|code)=([^&;\s]+)",
        r"\1=[REDACTED]",
        text,
    )
    return text[:2000]


def _normalise_url(payload: str) -> str:
    value = payload.strip()
    if value.lower().startswith("www."):
        return "https://" + value
    if "://" not in value and re.match(r"^[\w.-]+\.[a-zA-Z]{2,}([:/?#]|$)", value):
        return "https://" + value
    return value


def _classify_payload(payload: str) -> tuple[str, str]:
    value = payload.strip()
    lower = value.lower()
    if lower.startswith("wifi:"):
        return "Wi-Fi configuration", "Wi-Fi QR codes can contain network credentials."
    if lower.startswith("mailto:"):
        return "Email action", "This QR code prepares an email; review the recipient and message before sending."
    if lower.startswith(("tel:", "sms:")):
        return "Phone / SMS action", "This QR code may start a call or prepare a message. Review details before proceeding."
    if lower.startswith(("javascript:", "data:")):
        return "Executable / embedded payload", "This payload uses a scheme that should not be opened blindly."
    if lower.startswith("file:"):
        return "Local file reference", "This payload references a local file location rather than a normal website."
    if lower.startswith("intent:"):
        return "Application intent", "This payload may request an action in an installed application."
    if lower.startswith(("http://", "https://", "www.")):
        return "Web URL", "A website address was found. The app will inspect it offline only."
    if lower.startswith("ftp:"):
        return "FTP address", "This is a file-transfer address, not a standard HTTPS webpage."
    normalised = _normalise_url(value)
    try:
        parsed = urlsplit(normalised)
        parsed_scheme = parsed.scheme.lower()
    except ValueError:
        return "Malformed URL", "The URL could not be parsed cleanly. Do not use it until you can verify its structure."
    if parsed_scheme in {"http", "https"} and parsed.netloc:
        return "Web URL", "A website address was found. The app will inspect it offline only."
    return "Text / other", "No standard website URL was identified in this payload."


def analyze_payload(payload: str) -> dict:
    """Return a transparent, explainable risk assessment for a QR payload."""
    raw = str(payload or "").strip()
    if not raw:
        raise ValueError("Please provide a QR payload or upload an image containing a QR code.")
    if len(raw) > 10000:
        raise ValueError("The payload is unusually long. Please use a payload under 10,000 characters.")

    kind, summary = _classify_payload(raw)
    lower = raw.lower()
    indicators: list[dict] = []
    recommendations: list[str] = []
    score = 0

    def flag(label: str, points: int, severity: str, detail: str) -> None:
        nonlocal score
        score += points
        indicators.append({
            "indicator": label,
            "points": points,
            "severity": severity,
            "detail": detail,
        })

    # Dangerous schemes are handled explicitly and are never executed.
    if lower.startswith(("javascript:", "data:")):
        flag("Risky payload scheme", 100, "Critical", "This scheme can represent executable script or embedded content. Do not open it from an untrusted QR code.")
        recommendations.extend([
            "Do not open or copy this payload into a browser address bar.",
            "Use a plain-text viewer for investigation and ask the QR code owner for a trusted destination.",
        ])
    elif lower.startswith("file:"):
        flag("Local file reference", 75, "High", "The payload points to a local file location and may behave differently across devices.")
        recommendations.append("Do not open local file references from unknown QR codes.")
    elif lower.startswith("intent:"):
        flag("Application intent scheme", 40, "High", "The payload may try to route an action to a mobile application.")
        recommendations.append("Review the requested application action before proceeding.")
    elif lower.startswith("ftp:"):
        flag("Non-web transfer protocol", 25, "Moderate", "FTP is not the same as a standard HTTPS website and may not protect data in transit.")
        recommendations.append("Avoid sending credentials through untrusted file-transfer links.")

    normalised = _normalise_url(raw)
    try:
        parts = urlsplit(normalised)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError:
        parts = urlsplit("")
        scheme = ""
        host = ""
        if kind == "Malformed URL":
            flag("Malformed URL structure", 18, "Moderate", "The URL could not be parsed reliably. The destination is not evaluated further.")
    is_web_url = scheme in {"http", "https"} and bool(host)

    if is_web_url:
        if scheme == "http":
            flag("Unencrypted HTTP", 15, "Moderate", "The address uses HTTP rather than HTTPS, so the connection is not protected by TLS.")
            recommendations.append("Avoid entering passwords or payment information on an HTTP page.")

        # User information before @ can disguise the actual destination host.
        try:
            if parts.username is not None or parts.password is not None:
                flag("Embedded URL credentials", 30, "High", "The URL contains user-information fields before the destination host, a technique that can make links misleading.")
                recommendations.append("Read the actual hostname carefully; do not trust the brand text before the @ symbol.")
        except ValueError:
            flag("Malformed URL authority", 15, "Moderate", "The URL authority could not be parsed cleanly.")

        try:
            ipaddress.ip_address(host.strip("[]"))
            flag("IP-address destination", 18, "Moderate", "The website address uses a literal IP address instead of a conventional domain name. This is a review signal, not proof of an attack.")
        except ValueError:
            pass

        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
            if "xn--" in ascii_host:
                flag("Internationalized domain name", 18, "Moderate", "The hostname contains an IDN/punycode label. Similar-looking characters can be used to imitate another domain.")
        except UnicodeError:
            flag("Unusual hostname encoding", 12, "Moderate", "The hostname could not be converted cleanly using IDN rules.")

        if host in SHORTENER_DOMAINS or any(host.endswith("." + domain) for domain in SHORTENER_DOMAINS):
            flag("URL shortener", 18, "Moderate", "The address uses a known URL-shortening domain, which can conceal the final destination.")
            recommendations.append("Verify the final destination through a trusted preview or independent source before opening it.")

        if host.count(".") >= 4:
            flag("Many hostname levels", 8, "Low", "The hostname has several subdomain levels. Check which domain is actually registered.")

        if len(normalised) > 180:
            flag("Unusually long URL", 8, "Low", "The link is long enough to make manual inspection difficult.")

        # Check for suspicious brand mentions that do not match the brand's usual domain.
        for brand, legitimate_domain in BRAND_DOMAINS.items():
            if brand in host and host != legitimate_domain and not host.endswith("." + legitimate_domain):
                flag("Possible brand impersonation", 18, "High", f"The hostname contains '{brand}' but does not end in the expected domain '{legitimate_domain}'. Verify the domain independently.")
                recommendations.append("Visit the organization's official website using a saved bookmark or a manually typed address.")
                break

        for term, detail in SUSPICIOUS_TERMS.items():
            if term in (host + parts.path).lower():
                flag("Credential / urgency wording", 10, "Moderate", detail)
                break

        try:
            port = parts.port
            if port is not None and port not in {80, 443}:
                flag("Non-standard web port", 10, "Moderate", f"The URL specifies port {port}, which is less common for a normal public webpage.")
        except ValueError:
            flag("Malformed port", 12, "Moderate", "The URL contains an invalid port value.")

        query_keys = [key.lower() for key, _ in parse_qsl(parts.query, keep_blank_values=True)]
        if any(key in SENSITIVE_QUERY_KEYS or any(token in key for token in ("password", "token", "secret", "apikey", "session")) for key in query_keys):
            flag("Sensitive query parameter", 12, "Moderate", "The link contains a query parameter with a name commonly used for a token, session, password, or secret. The value is masked in this app's display and saved history.")
            recommendations.append("Do not share links that contain active access tokens or session identifiers.")

    elif not indicators and kind not in {"Wi-Fi configuration", "Email action", "Phone / SMS action", "Text / other"}:
        flag("Unsupported payload type", 10, "Low", "The payload is not a normal web URL and needs context before use.")

    # De-duplicate recommendations while retaining their original order.
    if not recommendations:
        recommendations.append("No obvious warning was triggered by these local checks. This does not prove the destination is safe.")
    recommendations.append("Do not open the destination directly from this report; verify it independently if you are unsure.")
    recommendations = list(dict.fromkeys(recommendations))

    score = min(100, score)
    if score >= 70:
        level, summary_line = "Critical", "Several serious warning signs were detected. Avoid opening this payload unless it is independently verified."
    elif score >= 45:
        level, summary_line = "High", "This payload has multiple warning signs and should be treated cautiously."
    elif score >= 20:
        level, summary_line = "Moderate", "Some warning signs were detected. Verify the destination before taking action."
    else:
        level, summary_line = "Low", "Few or no warning signs were detected by the selected offline rules. This is not a guarantee of safety."

    if is_web_url:
        safe_target = redact_sensitive_payload(normalised)
    else:
        safe_target = redact_sensitive_payload(raw)

    return {
        "payload": redact_sensitive_payload(raw),
        "kind": kind,
        "score": score,
        "level": level,
        "summary": summary_line,
        "description": summary,
        "target": safe_target,
        "indicators": indicators,
        "recommendations": recommendations,
        "analyzed_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "engine": "QRShield Offline Rules v1.0",
    }
