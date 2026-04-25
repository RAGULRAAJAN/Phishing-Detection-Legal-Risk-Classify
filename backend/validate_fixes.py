import sys
sys.path.append('.')
from core.ensemble import EnsembleAggregator

e = EnsembleAggregator('.')
e.initialize()

# Test Case 1: Subdomain match
eml1 = b"""From: alerts@corp.google.com
Subject: Your report is ready
Content-Type: text/html

<html><body>Click here: <a href="https://reports.google.com/123">View Report</a></body></html>
"""
res1 = e.analyze(eml1)
print(f"Subdomain Match Score: {res1['confidence']} (RF: {res1['ensemble_scores']['random_forest']}, BERT: {res1['ensemble_scores']['bert_nlp']})")
print(f"  SHAP: {res1['explanations']['shap']}")

# Test Case 2: Legit company email with external links (common FP)
eml2 = b"""From: newsletter@microsoft.com
Subject: Monthly Update
Content-Type: text/html

<html><body>
Follow us on <a href="https://twitter.com/microsoft">Twitter</a>.
Check out <a href="https://github.com/microsoft">GitHub</a>.
</body></html>
"""
res2 = e.analyze(eml2)
print(f"Legit Multiple Ext Links Score: {res2['confidence']} (RF: {res2['ensemble_scores']['random_forest']}, BERT: {res2['ensemble_scores']['bert_nlp']})")
print(f"  SHAP: {res2['explanations']['shap']}")

# Test Case 3: Simple plain text
eml3 = b"""From: boss@office.local
Subject: Meeting
Meeting at 3pm today.
"""
res3 = e.analyze(eml3)
print(f"Plain Text Score: {res3['confidence']}")
