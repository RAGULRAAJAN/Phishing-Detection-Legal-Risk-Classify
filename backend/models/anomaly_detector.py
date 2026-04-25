import joblib
import pandas as pd
import os

class IsolationForestAnomalyDetector:
    def __init__(self, model_path="if_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.feature_names = [
            "subject_len", "num_attachments", "total_links"
        ]

    def load(self):
        try:
            if not os.path.exists(self.model_path):
                return False
                
            self.model = joblib.load(self.model_path)
            return True
        except Exception as e:
            print(f"Warning: Could not load Isolation Forest from {self.model_path}: {e}")
            return False

    def predict(self, features_dict: dict) -> bool:
        """
        Returns True if the email is considered a routing or structural anomaly.
        """
        if not self.model:
            return False

        X_df = pd.DataFrame([{k: features_dict.get(k, 0.0) for k in self.feature_names}])
        
        try:
            # -1 for outliers, 1 for inliers
            prediction = self.model.predict(X_df)[0]
            # True if anomaly (outlier)
            is_anomaly = (prediction == -1)
            return is_anomaly
        except Exception as e:
            print(f"Isolation Forest Error: {e}")
            return False
