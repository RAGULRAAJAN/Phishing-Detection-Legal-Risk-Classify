import re

def evaluate_legal_risk(text: str, threat_score: float) -> tuple[list[str], list[str]]:
    """
    Evaluates the input text and its threat score against legal frameworks.
    Returns a tuple of (risk_tags, legal_violations).
    """
    risk_tags = []
    legal_violations = []

    text_lower = text.lower()

    # Only map legal violations if the threat score is reasonably high 
    # to avoid false positives on casual conversations.
    if threat_score < 0.40:
        return risk_tags, legal_violations

    # 1. Identity Theft / IT Act 66C
    # Looks for credential harvesting attempts.
    identity_theft_patterns = [
        r"\bpassword\b", r"\blogin\b", r"\bcredentials\b", 
        r"verify your account", r"reset.*password"
    ]
    if any(re.search(pat, text_lower) for pat in identity_theft_patterns):
        risk_tags.append("Identity Theft")
        legal_violations.append("IT Act 2000 - Section 66C (Identity Theft)")

    # 2. Cheating by Personation / IT Act 66D
    # Looks for financial urgency and impersonation tactics.
    personation_patterns = [
        r"\burgent\b", r"wire transfer", r"gift card", r"\bbank\b", 
        r"account suspended", r"invoice attached"
    ]
    if any(re.search(pat, text_lower) for pat in personation_patterns):
        risk_tags.append("Cheating by Personation")
        legal_violations.append("IT Act 2000 - Section 66D (Cheating by Personation)")

    # 3. Data Privacy Laws / DPDP Act 2023
    # Looks for exposure or requests for sensitive personal information.
    privacy_patterns = [
        r"\bssn\b", r"credit card", r"personal data", r"social security",
        r"\bdob\b", r"date of birth"
    ]
    if any(re.search(pat, text_lower) for pat in privacy_patterns):
        risk_tags.append("Data Privacy Compromise")
        legal_violations.append("Digital Personal Data Protection (DPDP) Act, 2023")

    return risk_tags, legal_violations
