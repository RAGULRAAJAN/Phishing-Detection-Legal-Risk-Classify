import json
import os

LOG_PATH = "logs/security_events.log"

def analyze_incident():
    if not os.path.exists(LOG_PATH):
        print(f"Error: Log file {LOG_PATH} not found.")
        return

    print("="*60)
    print("      INCIDENT RESPONSE INVESTIGATION REPORT")
    print("="*60)

    events = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except:
                continue

    # 1. Timeline Reconstruction
    print("\n[+] RECONSTRUCTING TIMELINE:")
    
    patient_zero = None
    iocs = []
    
    for event in events:
        ts = event.get("timestamp", "UNKNOWN")
        etype = event.get("event_type", "UNKNOWN")
        
        # Handle different log formats
        details = event.get("details") or event.get("results")
        if not details:
            continue
            
        if etype == "phishing_analysis":
            threat_score = details.get("threat_score", 0)
            risk_tags = details.get("risk_tags", [])
            print(f"[{ts}] PHISHING DETECTED: Score {threat_score}% - Tags: {', '.join(risk_tags)}")
            patient_zero = details
        
        elif etype.startswith("sysmon_"):
            if etype == "sysmon_1":
                proc = details.get("process_name")
                parent = details.get("parent_process")
                cmd = details.get("command_line")
                print(f"[{ts}] PROCESS CREATION: {proc} (Parent: {parent}) -> CMD: {cmd}")
                iocs.append(f"Process: {proc}")
            
            elif etype == "sysmon_3":
                dest = details.get("destination_ip")
                port = details.get("destination_port")
                print(f"[{ts}] NETWORK CONN: {details.get('process_name')} connected to {dest}:{port}")
                iocs.append(f"C2 IP: {dest}")
            
            elif etype == "sysmon_11":
                path = details.get("file_path")
                print(f"[{ts}] FILE CREATION: {details.get('process_name')} created {path}")
                iocs.append(f"File: {path}")

    # 2. Executive Summary
    print("\n" + "="*60)
    print("      EXECUTIVE SUMMARY")
    print("="*60)
    
    if patient_zero:
        print(f"Status:        INCIDENT CONFIRMED")
        print(f"Infection Vector: Social Engineering (Phishing)")
        legal_v = patient_zero.get('legal_violations', [])
        if legal_v:
            # Handle list of dicts or list of strings
            if isinstance(legal_v[0], dict):
                v_titles = [v['title'] for v in legal_v]
            else:
                v_titles = legal_v
            print(f"Legal Impact:  {', '.join(v_titles)}")
    else:
        print("Status:        INVESTIGATION INCONCLUSIVE")

    print("\n[+] INDICATORS OF COMPROMISE (IOCs):")
    for ioc in sorted(list(set(iocs))):
        print(f" - {ioc}")

    print("\n[+] REMEDIATION STEPS:")
    print(" 1. Isolate WKSTN-092 from the network immediately.")
    print(" 2. Kill all processes associated with 'security_patch.exe'.")
    print(" 3. Block C2 IP (185.199.110.153) at the perimeter firewall.")
    print(" 4. Perform a password reset for CORP\\Victim.")
    print(" 5. Delete temporary file: C:\\Users\\Victim\\AppData\\Local\\Temp\\stolen_data.zip")
    print("="*60)

if __name__ == "__main__":
    analyze_incident()
