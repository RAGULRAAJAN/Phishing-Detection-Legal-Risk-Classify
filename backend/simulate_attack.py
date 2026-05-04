


import requests
import time
import json

BASE_URL = "http://127.0.0.1:8000"
API_KEY = "SOC-API-KEY-123"
HEADERS = {"X-API-Key": API_KEY}

def run_simulation():
    print("[*] Starting Phishing-to-Malware Simulation...")
    
    # 1. Initial Phishing Email
    phish_email = {
        "text": "URGENT: Your account has been suspended. Please click here to verify: http://malicious-update.com/verify-account. Download the attachment 'security_patch.exe' to secure your system."
    }
    
    print("[+] Phase 1: Sending Phishing Email for analysis...")
    resp = requests.post(f"{BASE_URL}/analyze", json=phish_email, headers=HEADERS)
    result = resp.json()
    print(f"    Detection Result: {'PHISHING' if result['is_phishing'] else 'CLEAN'}")
    print(f"    Threat Score: {result['threat_score']}%")
    
    time.sleep(2)
    
    # 2. Simulated Click & Execution
    print("[+] Phase 2: Simulating User Execution (security_patch.exe)...")
    execution_events = [
        {
            "event_type": "sysmon_1", # Process Creation
            "process_name": "security_patch.exe",
            "parent_process": "outlook.exe",
            "command_line": "C:\\Users\\Victim\\Downloads\\security_patch.exe",
            "user": "CORP\\Victim",
            "host": "WKSTN-092"
        },
        {
            "event_type": "sysmon_1", # Child Process
            "process_name": "cmd.exe",
            "parent_process": "security_patch.exe",
            "command_line": "cmd.exe /c powershell -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\exfil.ps1",
            "user": "CORP\\Victim",
            "host": "WKSTN-092"
        },
        {
            "event_type": "sysmon_3", # Network Connection
            "process_name": "powershell.exe",
            "destination_ip": "185.199.110.153",
            "destination_port": 443,
            "protocol": "tcp",
            "host": "WKSTN-092"
        },
        {
            "event_type": "sysmon_11", # File Created
            "process_name": "powershell.exe",
            "file_path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\stolen_data.zip",
            "host": "WKSTN-092"
        }
    ]
    
    for event in execution_events:
        requests.post(f"{BASE_URL}/api/v1/simulate-execution", json=event, headers=HEADERS)
        print(f"    Logged: {event['event_type']} - {event.get('process_name') or event.get('file_path')}")
        time.sleep(1)

    print("\n[*] Simulation Complete. Logs generated in backend/logs/security_events.log")

if __name__ == "__main__":
    # Note: Ensure backend is running before executing this
    try:
        run_simulation()
    except Exception as e:
        print(f"Error: {e}. Is the backend server running at {BASE_URL}?")
