import sys
sys.path.append('.')
from core.ensemble import EnsembleAggregator

e = EnsembleAggregator('.')
e.initialize()

# Test Case: Blatant Phishing
eml_phish = b"""From: security@paypal-verify.com
To: user@gmail.com
Subject: Your account has been suspended!
Content-Type: text/html

<html><body>
Your PayPal account has been suspended due to suspicious activity.
Please log in here to verify your identity: <a href="http://paypal-secure-login.net/verify">Verify Now</a>
</body></html>
"""
res = e.analyze(eml_phish)
print(f"Phishing Score: {res['confidence']}")
print(f"Ensemble Scores: {res['ensemble_scores']}")
print(f"Is Phishing? {res['is_phishing']}")
print(f"Extracted Features: {res['extracted_features']}")

# Test Case: Banking Phish
eml_bank = b"""From: alert@wellsfargo.com
To: user@gmail.com
Subject: Urgent: Unauthorized transaction
Content-Type: text/html

<html><body>
A transfer of $5,000 was initiated. If this was not you, cancel it here: 
<a href="http://wellsfargo-security.top/cancel">Cancel Transaction</a>
</body></html>
"""
res2 = e.analyze(eml_bank)
print(f"Bank Phish Score: {res2['confidence']}")
print(f"Is Phishing? {res2['is_phishing']}")
