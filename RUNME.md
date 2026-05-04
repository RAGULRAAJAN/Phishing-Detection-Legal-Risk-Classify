# Phishing Detection & Incident Response Simulation

This project combines a Hybrid ML Phishing Detection engine with a Simulated Incident Response (IR) lab.

## Prerequisites
- Python 3.9+
- Pip (Python package manager)

## 1. Setup Environment
Open your terminal and run:
```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Start the Backend API
Run the FastAPI server (keep this terminal open):
```powershell
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

## 3. Run the Phishing-to-Malware Simulation
In a **new** terminal (ensure venv is active), run the simulation script to generate attack logs:
```powershell
cd backend
python simulate_attack.py
```
*This simulates a user receiving a phishing email, clicking it, and the resulting malware execution (C2 connection and file staging).*

## 4. Generate Incident Response Report
Analyze the logs and generate the IR investigation report:
```powershell
cd backend
python ir_investigator.py
```

## Project Components
- `main.py`: The FastAPI backend with ML detection and security logging.
- `simulate_attack.py`: Script to inject simulated "Sysmon" events into the logs.
- `ir_investigator.py`: SOC tool to reconstruct the attack timeline and IOCs.
- `logs/security_events.log`: The unified log file for all security events.
