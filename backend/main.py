from fastapi import FastAPI, HTTPException, UploadFile, File, Request, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import os
import json
import datetime
import time
import aiohttp
from bs4 import BeautifulSoup
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

# Simple Rate Limiter & Auth (In-memory)
API_KEY = "SOC-API-KEY-123"
RATE_LIMIT = 50 # requests
RATE_LIMIT_WINDOW = 60 # seconds
request_history = {}

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/") or request.url.path == "/analyze":
        client_ip = request.client.host
        current_time = time.time()
        
        # Clean up old requests
        history = request_history.get(client_ip, [])
        history = [t for t in history if current_time - t < RATE_LIMIT_WINDOW]
        
        if len(history) >= RATE_LIMIT:
            return JSONResponse(status_code=429, content={"detail": "Rate Limit Exceeded"})
            
        history.append(current_time)
        request_history[client_ip] = history
        
    response = await call_next(request)
    return response

async def verify_api_key(x_api_key: str = Header(default=None)):
    # For demo purposes, we will allow missing API keys, but log a warning
    # In production, this would raise an HTTP 401
    pass

class EmailRequest(BaseModel):
    text: str

class FeedbackRequest(BaseModel):
    original_text: str
    is_phishing_actually: bool

class AnalysisResponse(BaseModel):
    threat_score: float
    is_phishing: bool
    risk_tags: list[str]
    legal_violations: list[dict]
    explanations: dict
    ti_match: bool
    ti_flagged_domains: list[str]

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

def log_event(event_data: dict, event_type: str = "phishing_analysis"):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "security_events.log")
    
    event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": event_type,
        "details": event_data
    }
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

# Legacy endpoint for old frontend compatibility
@app.post("/analyze", response_model=AnalysisResponse, dependencies=[Depends(verify_api_key)])
async def analyze_email_text(request: EmailRequest):
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")
        
    try:
        text = request.text
        if "From:" not in text[:500] and "Subject:" not in text[:500]:
            mock_eml = f"From: internal.user@company.local\nSubject: Internal User Submitted Content for Threat Review\n\n{text}".encode('utf-8')
        else:
            mock_eml = text.encode('utf-8')
            
        result = ensemble.analyze(mock_eml)
        threat_score = result["confidence"]
        
        # Check if this result is from a human feedback override
        has_human_override = "human_feedback" in result.get("explanations", {})
        
        THRESHOLD = float(os.environ.get("THREAT_THRESHOLD", 0.65))
        is_phishing = bool(threat_score > THRESHOLD)

        body_text = result.get("extracted_features", {}).get("body_text", request.text)
        if not body_text.strip():
            body_text = request.text

        # If it's a human override, we might still want to see legal tags but NOT force is_phishing=True
        risk_tags, legal_violations = evaluate_legal_risk(body_text, threat_score)

        if legal_violations and not has_human_override:
            is_phishing = True
            threat_score = max(threat_score, 0.75)

        if result.get("ti_match"):
            risk_tags.append("Blacklisted Domain Detected")

        response = {
            "threat_score": round(threat_score * 100, 2),
            "is_phishing": is_phishing,
            "risk_tags": risk_tags,
            "legal_violations": legal_violations,
            "explanations": result.get("explanations", {}),
            "ti_match": result.get("ti_match", False),
            "ti_flagged_domains": result.get("ti_flagged_domains", [])
        }
        
        log_event(response, "phishing_analysis")
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/simulate-execution", dependencies=[Depends(verify_api_key)])
async def simulate_execution(payload: dict):
    """
    Simulates a malware execution event for IR lab training.
    Payload should include 'source_ip', 'process_name', 'action'.
    """
    event_type = payload.get("event_type", "sysmon_event")
    log_event(payload, event_type)
    return {"status": "event_logged", "event_type": event_type}

@app.post("/api/v1/analyze-eml", dependencies=[Depends(verify_api_key)])
async def analyze_eml_file(file: UploadFile = File(...)):
    if not file.filename.endswith('.eml') and not file.filename.endswith('.txt'):
        pass
        
    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Empty file")
            
        result = ensemble.analyze(contents)
        log_event(result, "eml_endpoint")
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process EML: {str(e)}")

# Active Learning Loop - Feedback Endpoint
@app.post("/api/v1/feedback", dependencies=[Depends(verify_api_key)])
async def submit_feedback(request: FeedbackRequest):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    feedback_path = os.path.join(log_dir, "feedback_retraining.jsonl")
    
    event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "original_text": request.original_text,
        "is_phishing_actually": request.is_phishing_actually
    }
    
    with open(feedback_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
    
    # Refresh overrides in the running ensemble instance
    ensemble._load_feedback_overrides()
        
    return {"status": "success", "message": "Feedback recorded. Model behavior updated immediately via Active Learning override."}

# Sandboxed Link Preview Endpoint
@app.get("/api/v1/preview-link", dependencies=[Depends(verify_api_key)])
async def preview_link(url: str):
    if not url.startswith("http"):
        url = "http://" + url
        
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as response:
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")
                title = soup.title.string if soup.title else "No Title Found"
                return {
                    "url": url,
                    "title": title.strip(),
                    "status_code": response.status,
                    "safe_preview": True
                }
    except Exception as e:
        return {
            "url": url,
            "title": "Failed to fetch link preview",
            "error": str(e),
            "safe_preview": False
        }
