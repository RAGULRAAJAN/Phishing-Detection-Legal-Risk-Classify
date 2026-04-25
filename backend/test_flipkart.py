import sys
sys.path.append('.')
from core.ensemble import EnsembleAggregator

e = EnsembleAggregator('.')
e.initialize()

# The user's email source
eml_content = b"""Delivered-To: ragul18012006@gmail.com
Received: by 2002:a05:7011:990:b0:500:c26e:b238 with SMTP id im16csp1616715mdb;
        Mon, 20 Apr 2026 04:34:42 -0700 (PDT)
From: "Flipkart.com" <noreply@rmo.flipkart.com>
To: null <ragul18012006@gmail.com>
Subject: New device login detected in your Flipkart account
Message-ID: <d5dce2dc-b7d0-6f83-ac93-bd6191df656e@rmo.flipkart.com>
Date: Mon, 20 Apr 2026 11:34:39 +0000
Content-Type: text/plain

Hi Ragul, a new login was detected.
"""

res = e.analyze(eml_content)
print(f"Confidence: {res['confidence']}")
print(f"Ensemble Scores: {res['ensemble_scores']}")
print(f"SHAP: {res['explanations']['shap']}")
print(f"Extracted Features: {res['extracted_features']}")
