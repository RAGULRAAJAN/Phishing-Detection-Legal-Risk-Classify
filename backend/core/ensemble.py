from models.rf_classifier import RFPhishingClassifier
from models.bert_classifier import BERTPhishingClassifier
from models.anomaly_detector import IsolationForestAnomalyDetector
from core.feature_extraction import extract_features_from_eml
import os
import json

# Mock Threat Intelligence Blacklist (e.g., PhishTank, Google Safe Browsing)
TI_BLACKLIST = {
    "secure-login-update-account.com",
    "apple-id-verify-alert.net",
    "paypal-resolution-center.info",
    "free-giftcard-giveaway.xyz",
    "evil-phishing-domain.com"
}

class EnsembleAggregator:
    def __init__(self, model_dir="."):
        self.rf = RFPhishingClassifier(model_path=f"{model_dir}/rf_model.pkl")
        self.bert = BERTPhishingClassifier(local_path=f"{model_dir}/bert_model_dir")
        self.iforest = IsolationForestAnomalyDetector(model_path=f"{model_dir}/if_model.pkl")
        
        self.rf_loaded = False
        self.bert_loaded = False
        self.iforest_loaded = False
        self.feedback_overrides = {}

    def initialize(self):
        self.rf_loaded = self.rf.load()
        self.bert_loaded = self.bert.load()
        self.iforest_loaded = self.iforest.load()
        self._load_feedback_overrides()

    def _load_feedback_overrides(self):
        """Loads human-in-the-loop feedback to override model decisions."""
        feedback_path = "logs/feedback_retraining.jsonl"
        if os.path.exists(feedback_path):
            try:
                with open(feedback_path, "r", encoding="utf-8") as f:
                    for line in f:
                        data = json.loads(line)
                        # Store the latest feedback for each unique text, stripped to match extraction
                        self.feedback_overrides[data["original_text"].strip()] = data["is_phishing_actually"]
                print(f"Loaded {len(self.feedback_overrides)} feedback overrides.")
            except Exception as e:
                print(f"Warning: Could not load feedback overrides: {e}")

    def analyze(self, eml_bytes: bytes) -> dict:
        # 1. Feature Extraction
        features_dict = extract_features_from_eml(eml_bytes)
        body_text = features_dict.get("body_text", "").strip()
        extracted_domains = features_dict.get("extracted_domains", [])
        
        # 2. Check for User Feedback Overrides (Active Learning)
        # If the user has manually corrected this specific email before, we honor it immediately.
        if body_text in self.feedback_overrides:
            is_phishing_override = self.feedback_overrides[body_text]
            return {
                "action": "block" if is_phishing_override else "allow",
                "confidence": 1.0 if is_phishing_override else 0.0,
                "is_phishing": is_phishing_override,
                "ensemble_scores": {"random_forest": 0.0, "bert_nlp": 0.0, "isolation_forest_anomaly": False},
                "explanations": {"human_feedback": "This result was overridden by manual security analyst feedback."},
                "ti_match": False,
                "ti_flagged_domains": [],
                "extracted_features": features_dict
            }

        # 3. Threat Intel Lookup
        ti_match = False
        ti_flagged_domains = []
        for domain in extracted_domains:
            if domain in TI_BLACKLIST:
                ti_match = True
                ti_flagged_domains.append(domain)
        
        # 4. Base Predictions
        rf_score, explanations = self.rf.predict(features_dict) if self.rf_loaded else (0.5, {})
        bert_score = self.bert.predict(body_text) if self.bert_loaded else 0.5
        is_anomaly = self.iforest.predict(features_dict) if self.iforest_loaded else False
        
        # 5. Aggregation Logic
        # Weights: 60% RF, 40% BERT
        final_score = (rf_score * 0.60) + (bert_score * 0.40)
        
        # If Threat Intel flagged a domain, elevate the score to CRITICAL
        if ti_match:
            final_score = max(final_score, 0.95)
            
        # 6. Trusted Domain Bonus
        trusted_domains = ["flipkart.com", "amazon.in", "google.com", "microsoft.com", "apple.com", "github.com"]
        sender_email = features_dict.get("sender_email", "")
        sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
        
        def get_base(d):
            parts = d.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else d

        if get_base(sender_domain) in trusted_domains:
            if features_dict.get("FrequentDomainNameMismatch", 0) == 0 and not ti_match:
                # Apply a reputation bonus, but don't completely clear a high-confidence threat
                if final_score < 0.8:
                    final_score -= 0.20
                
        final_score = max(0.0, min(final_score, 1.0)) # Clamp between 0 and 1
        
        BLOCK_THRESHOLD = 0.50
        action = "block" if final_score > BLOCK_THRESHOLD else "allow"
        
        return {
            "action": action,
            "confidence": round(final_score, 4),
            "is_phishing": final_score > BLOCK_THRESHOLD,
            "ensemble_scores": {
                "random_forest": round(rf_score, 4),
                "bert_nlp": round(bert_score, 4),
                "isolation_forest_anomaly": is_anomaly
            },
            "explanations": explanations,
            "ti_match": ti_match,
            "ti_flagged_domains": ti_flagged_domains,
            "extracted_features": {
                "PctExtHyperlinks": features_dict.get("PctExtHyperlinks"),
                "FrequentDomainNameMismatch": features_dict.get("FrequentDomainNameMismatch"),
                "PctExtNullSelfRedirectHyperlinksRT": features_dict.get("PctExtNullSelfRedirectHyperlinksRT"),
                "total_links": features_dict.get("total_links"),
                "body_text": features_dict.get("body_text", "")
            }
        }
