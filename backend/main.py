from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import json
import datetime
from legal_engine import evaluate_legal_risk
from core.ensemble import EnsembleAggregator

app = FastAPI(title="Phishing Detection & Legal Risk API (Hybrid ML Pipeline)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize global ensemble aggregator
ensemble = EnsembleAggregator(model_dir=".")

class EmailRequest(BaseModel):
    text: str

class AnalysisResponse(BaseModel):
    threat_score: float
    is_phishing: bool
    risk_tags: list[str]
    legal_violations: list[str]

@app.on_event("startup")
async def load_models():
    """Loads the ML models on Fastapi startup."""
    print("Initializing Hybrid ML Ensemble...")
    ensemble.initialize()
    if not ensemble.rf_loaded:
        print("Warning: RF Model not loaded. Did you run train_pipeline.py?")
    if not ensemble.bert_loaded:
        print("Warning: BERT Model not loaded. Did you run train_pipeline.py?")
    if not ensemble.iforest_loaded:
        print("Warning: Isolation Forest not loaded.")

def log_event(response_data: dict, email_source: str):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "security_events.log")
    
    event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": "phishing_analysis",
        "input": "text_or_eml_snippet",
        "results": response_data
    }
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

# Legacy endpoint for old frontend compatibility
@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_email_text(request: EmailRequest):
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")
        
    try:
        # We can pass raw text into ensemble by faking an .eml, or directly using bert
        # To maintain compatibility, we use bert score directly from ensemble if available
        mock_eml = f"Subject: None\n\n{request.text}".encode('utf-8')
        result = ensemble.analyze(mock_eml)
        threat_score = result["confidence"]
        
        THRESHOLD = float(os.environ.get("THREAT_THRESHOLD", 0.3))
        is_phishing = bool(threat_score > THRESHOLD)
        
        risk_tags, legal_violations = evaluate_legal_risk(request.text, threat_score)
        
        response = {
            "threat_score": round(threat_score * 100, 2),
            "is_phishing": is_phishing,
            "risk_tags": risk_tags,
            "legal_violations": legal_violations
        }
        
        log_event(response, "text_endpoint")
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# New Pipeline Endpoint for Java Firewall
@app.post("/api/v1/analyze-eml")
async def analyze_eml_file(file: UploadFile = File(...)):
    if not file.filename.endswith('.eml') and not file.filename.endswith('.txt'):
        pass # Allow anyway for testing
        
    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Empty file")
            
        result = ensemble.analyze(contents)
        
        log_event(result, "eml_endpoint")
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process EML: {str(e)}")
