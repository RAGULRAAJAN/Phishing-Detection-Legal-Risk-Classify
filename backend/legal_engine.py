import re

def evaluate_legal_risk(text: str, threat_score: float) -> tuple[list[str], list[dict]]:
    """
    Evaluates the input text against international legal frameworks.
    Returns a tuple of (risk_tags, legal_violations) where legal_violations are dicts with details.
    """
    risk_tags = []
    legal_violations = []

    text_lower = text.lower()

    # 1. Identity Theft / IT Act 66C
    identity_theft_patterns = [
        r"\bpassword\b", r"\blogin\b", r"\bcredentials\b", 
        r"verify your account", r"reset.*password"
    ]
    if any(re.search(pat, text_lower) for pat in identity_theft_patterns):
        risk_tags.append("Identity Theft")
        legal_violations.append({
            "title": "IT Act 2000 - Section 66C",
            "description": "Punishment for identity theft. The payload indicates attempts to harvest passwords or spoof identities."
        })

    # 2. Cheating by Personation / IT Act 66D
    personation_patterns = [
        r"\burgent\b", r"wire transfer", r"gift card", r"\bbank\b", 
        r"account suspended", r"invoice attached"
    ]
    if any(re.search(pat, text_lower) for pat in personation_patterns):
        risk_tags.append("Cheating by Personation")
        legal_violations.append({
            "title": "IT Act 2000 - Section 66D",
            "description": "Punishment for cheating by personation by using a computer resource. The payload involves financial impersonation."
        })

    # 3. Data Privacy / DPDP Act 2023 & GDPR (EU)
    privacy_patterns = [
        r"\bssn\b", r"credit card", r"personal data", r"social security",
        r"\bdob\b", r"date of birth", r"national insurance"
    ]
    if any(re.search(pat, text_lower) for pat in privacy_patterns):
        risk_tags.append("Data Privacy Compromise")
        legal_violations.append({
            "title": "DPDP Act, 2023 & GDPR (Art. 5)",
            "description": "Violation of principles relating to processing of personal data. The payload demonstrates risks to data privacy by soliciting PII (Personally Identifiable Information)."
        })

    # 4. California Consumer Privacy Act (CCPA)
    ccpa_patterns = [
        r"driver's license", r"passport number", r"financial account"
    ]
    if any(re.search(pat, text_lower) for pat in ccpa_patterns):
        risk_tags.append("CCPA Violation Risk")
        legal_violations.append({
            "title": "CCPA (Cal. Civ. Code § 1798.150)",
            "description": "Unauthorized access and exfiltration, theft, or disclosure of a consumer's nonencrypted and nonredacted personal information."
        })

    if threat_score > 0.65 and not legal_violations:
        risk_tags.append("General Cyber Threat")
        legal_violations.append({
            "title": "IT Act 2000 - Section 66",
            "description": "Computer related offences and general malicious cyber activity detected."
        })

    return risk_tags, legal_violations

