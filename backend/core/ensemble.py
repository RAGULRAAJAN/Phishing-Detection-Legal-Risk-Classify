from models.rf_classifier import RFPhishingClassifier
from models.bert_classifier import BERTPhishingClassifier
from models.anomaly_detector import IsolationForestAnomalyDetector
from core.feature_extraction import extract_features_from_eml

class EnsembleAggregator:
    def __init__(self, model_dir="."):
        self.rf = RFPhishingClassifier(model_path=f"{model_dir}/rf_model.pkl")
        self.bert = BERTPhishingClassifier(local_path=f"{model_dir}/bert_model_dir")
        self.iforest = IsolationForestAnomalyDetector(model_path=f"{model_dir}/if_model.pkl")
        
        self.rf_loaded = False
        self.bert_loaded = False
        self.iforest_loaded = False

    def initialize(self):
        self.rf_loaded = self.rf.load()
        self.bert_loaded = self.bert.load()
        self.iforest_loaded = self.iforest.load()
        
    def analyze(self, eml_bytes: bytes) -> dict:
        # 1. Feature Extraction
        features_dict = extract_features_from_eml(eml_bytes)
        body_text = features_dict.get("body_text", "")
        
        # 2. Base Predictions
        rf_score, explanations = self.rf.predict(features_dict) if self.rf_loaded else (0.5, {})
        bert_score = self.bert.predict(body_text) if self.bert_loaded else 0.5
        is_anomaly = self.iforest.predict(features_dict) if self.iforest_loaded else False
        
        # 3. Aggregation Logic
        # Weights: 60% RF, 40% BERT
        final_score = (rf_score * 0.60) + (bert_score * 0.40)
        
        # Isolation forest boosts score if anomaly detected
        if is_anomaly:
            final_score += 0.15
            
        final_score = min(final_score, 1.0) # Cap at 1.0
        
        BLOCK_THRESHOLD = 0.65
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
            "extracted_features": {
                "PctExtHyperlinks": features_dict.get("PctExtHyperlinks"),
                "FrequentDomainNameMismatch": features_dict.get("FrequentDomainNameMismatch"),
                "PctExtNullSelfRedirectHyperlinksRT": features_dict.get("PctExtNullSelfRedirectHyperlinksRT"),
                "total_links": features_dict.get("total_links")
            }
        }
