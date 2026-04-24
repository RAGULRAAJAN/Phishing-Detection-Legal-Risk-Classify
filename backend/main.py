from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import os
import json
import datetime
from legal_engine import evaluate_legal_risk

app = FastAPI(title="Phishing Detection & Legal Risk API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global dict to store the model
model_data = {}

class EmailRequest(BaseModel):
    text: str

class AnalysisResponse(BaseModel):
    threat_score: float
    is_phishing: bool
    risk_tags: list[str]
    legal_violations: list[str]

@app.on_event("startup")
async def load_model():
    """Loads the pre-trained ML model on Fastapi startup."""
    model_path = "phishing_model.pkl"
    if not os.path.exists(model_path):
        # We enforce that the model should be present (built during docker build)
        raise RuntimeError(f"Model not found at {model_path}. Did train_model.py run?")
    try:
        model_data["model"] = joblib.load(model_path)
        print("Scikit-learn model loaded successfully.")
    except Exception as e:
        raise RuntimeError(f"Error loading model: {str(e)}")

def log_event(response_data: dict, email_text: str):
    """
    Simulates writing to a structured JSON log for a SIEM (e.g., Splunk).
    Splunk commonly ingests lines of JSON text.
    """
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "security_events.log")
    
    event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": "phishing_analysis",
        "input_text": email_text,
        "results": response_data
    }
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailRequest):
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")
        
    model = model_data.get("model")
    if model is None:
        raise HTTPException(status_code=500, detail="Model is not loaded.")

    try:
        # Predict probability for the positive class (phishing = 1)
        prob = model.predict_proba([request.text])[0]
        # Depending on the classes order in model.classes_, find the index for '1'
        # In our mock dataset, classes are [0, 1]. So index 1 is phishing probability.
        classes = list(model.classes_)
        if 1 in classes:
            phishing_idx = classes.index(1)
            threat_score = float(prob[phishing_idx])
        else:
            # Fallback if classes are somehow different
            threat_score = float(prob[1]) if len(prob) > 1 else 0.0

        THRESHOLD = float(os.environ.get("THREAT_THRESHOLD", 0.3))
        is_phishing = bool(threat_score > THRESHOLD)
        
        # Pass through the Legal Engine
        risk_tags, legal_violations = evaluate_legal_risk(request.text, threat_score)
        
        response = {
            "threat_score": round(threat_score * 100, 2), # convert to percentage
            "is_phishing": is_phishing,
            "risk_tags": risk_tags,
            "legal_violations": legal_violations
        }
        
        # Log the event locally for Splunk ingestion
        log_event(response, request.text)
        
        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
