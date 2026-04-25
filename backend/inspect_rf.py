import joblib
import pandas as pd
import numpy as np

data = joblib.load('rf_model.pkl')
rf = data['model']

# Test a "perfectly legitimate" set of features
# subject_len, has_sender, num_attachments, PctExtHyperlinks, PctExtNull..., FreqDomainMismatch, total_links
test_features = [
    [50, 1, 0, 0.0, 0.0, 0, 0], # Corp email, no links, long subject
    [20, 1, 0, 0.0, 0.0, 0, 0], # Corp email, no links, short subject
    [50, 1, 0, 1.0, 1.0, 1, 5], # Phishing-like: many ext links
]

feature_names = [
    "subject_len", "has_sender", "num_attachments", 
    "PctExtHyperlinks", "PctExtNullSelfRedirectHyperlinksRT", 
    "FrequentDomainNameMismatch", "total_links"
]

X = pd.DataFrame(test_features, columns=feature_names)
probs = rf.predict_proba(X)
print("Probs (Ham, Phishing):")
for i, p in enumerate(probs):
    print(f"Case {i}: {p}")
