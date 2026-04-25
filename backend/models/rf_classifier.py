import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import shap
import lime.lime_tabular
import os

class RFPhishingClassifier:
    def __init__(self, model_path="rf_model.pkl"):
        # Expecting path relative to where main app runs, usually backend/
        self.model_path = model_path
        self.model = None
        self.explainer_shap = None
        self.explainer_lime = None
        self.feature_names = [
            "subject_len", "has_sender", "num_attachments", 
            "PctExtHyperlinks", "PctExtNullSelfRedirectHyperlinksRT", 
            "FrequentDomainNameMismatch", "total_links"
        ]
        self.X_train_bg = None

    def load(self):
        try:
            if not os.path.exists(self.model_path):
                return False
                
            data = joblib.load(self.model_path)
            self.model = data["model"]
            self.X_train_bg = data.get("X_train_bg")
            
            if self.X_train_bg is not None and len(self.X_train_bg) > 0:
                self.explainer_shap = shap.TreeExplainer(self.model)
                self.explainer_lime = lime.lime_tabular.LimeTabularExplainer(
                    self.X_train_bg, feature_names=self.feature_names, 
                    class_names=["Ham", "Phishing"], discretize_continuous=True
                )
            return True
        except Exception as e:
            print(f"Warning: Could not load RF model from {self.model_path}: {e}")
            return False

    def predict(self, features_dict: dict):
        if not self.model:
            return 0.0, {}

        X_df = pd.DataFrame([{k: features_dict.get(k, 0.0) for k in self.feature_names}])
        
        prob = self.model.predict_proba(X_df)[0]
        classes = list(self.model.classes_)
        phish_idx = classes.index(1) if 1 in classes else 1
        score = float(prob[phish_idx])
        
        explanations = {"shap": {}, "lime": []}
        
        try:
            if self.explainer_shap:
                try:
                    shap_vals = self.explainer_shap.shap_values(X_df)
                    # Handle binary classification outputs based on shap version
                    vals = shap_vals[1][0] if isinstance(shap_vals, list) else shap_vals[0]
                    # sometimes shape is (num_features, 2), check dimensions
                    if len(vals.shape) > 1 and vals.shape[1] == 2:
                        vals = vals[:, 1]
                    explanations["shap"] = {self.feature_names[i]: float(vals[i]) for i in range(len(self.feature_names))}
                except Exception as e:
                    explanations["shap_error"] = str(e)
                
            if self.explainer_lime and self.X_train_bg is not None:
                try:
                    exp = self.explainer_lime.explain_instance(X_df.iloc[0].values, self.model.predict_proba, num_features=3)
                    explanations["lime"] = [{"feature": k, "weight": float(v)} for k, v in exp.as_list()]
                except Exception as e:
                    explanations["lime_error"] = str(e)
        except Exception as overall_err:
            print(f"Error generating explanations: {overall_err}")
            
        return score, explanations
