import sys
sys.path.append('.')
from core.ensemble import EnsembleAggregator
from legal_engine import evaluate_legal_risk

e = EnsembleAggregator('.')
e.initialize()

eml_bank = b"""From: alert@wellsfargo.com
To: user@gmail.com
Subject: Urgent: Unauthorized transaction
Content-Type: text/html

<html><body>
A transfer of $5,000 was initiated. If this was not you, cancel it here: 
<a href="http://wellsfargo-security.top/cancel">Cancel Transaction</a>
</body></html>
"""
res = e.analyze(eml_bank)
risk_tags, legal_vios = evaluate_legal_risk(eml_bank.decode('utf-8'), res['confidence'])

print(f"Confidence: {res['confidence']}")
print(f"Risk Tags: {risk_tags}")
print(f"Legal Violations: {legal_vios}")
