import time
import os
import re
import json
import boto3
from datetime import datetime

LOG_FILE = "/var/log/secure"
EXCHANGE_FILE = "/home/nrobertson138/projects/Project-Aegis-Enterprise/telemetry_exchange.json"
S3_BUCKET = "aegis-track-logs-nicholas"

# Initialize Boto3 Client
s3_client = boto3.client('s3')

print("[*] Aegis-Track Initialized on Node: localhost.localdomain")
print(f"[*] Monitoring: {LOG_FILE}")
print(f"[*] Out-of-Band Cloud Pipeline Enabled -> S3://{S3_BUCKET}")

def upload_to_s3(payload, incident_id):
    now = datetime.now()
    s3_key = f"alerts/localhost.localdomain/{now.strftime('%Y/%m/%d')}/incident_{incident_id}.json"
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=json.dumps(payload, indent=4),
            ContentType="application/json"
        )
        print(f"[CLOUD SUCCESS] Immutable log archived -> {s3_key}")
    except Exception as e:
        print(f"[!] Cloud Archival Failed: {str(e)}")

# Safe file tailing and monitoring loop
if not os.path.exists(LOG_FILE):
    print(f"[!] Target log path {LOG_FILE} missing.")
    exit(1)

with open(LOG_FILE, "r", buffering=1) as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue
        
        if "Failed password" in line:
            print("[CRITICAL INTERVENTION] Full-spectrum audit alert generated for SSH Brute Force.")
            incident_id = os.urandom(4).hex()
            
            details = {
                "incident_id": incident_id,
                "timestamp": datetime.now().isoformat(),
                "node": "localhost.localdomain",
                "threat_signature": "SSH Brute Force Attempt",
                "raw_log": line.strip()
            }

            # Master Payload mapping exactly to the Risk Engine
            payload = {
                "telemetry_metadata": {
                    "event_id": incident_id,
                    "timestamp_utc": datetime.now().isoformat(),
                    "origin_host": "localhost.localdomain",
                    "threat_signature": "SSH Brute Force Attempt",
                    "raw_log": line.strip()
                },
                "security_incident_details": {
                    "incident_id": incident_id,
                    "raw_cvss_base_score": 7.5,
                    "attack_vector": "SSH Brute Force",
                    "mitre_attack_id": "T1110.001",
                    "threat_signature": "SSH Brute Force Attempt"
                },
                "continuous_control_audit": {
                    "control_id": "AC-7",
                    "control_name": "Unsuccessful Logon Attempts",
                    "framework": "NIST SP 800-53 R5",
                    "audit_status": "FAIL",
                    "firewall_posture": "BLOCKING"
                },
                "identity_context": {
                    "target_user": "root" if "root" in line else "unknown_service_account",
                    "source_ip": "127.0.0.1",
                    "authentication_protocol": "SSHv2",
                    "asset_criticality": "High",
                    "iam_status": "UNAUTHORIZED"
                }
            }

            # Export to local pipeline exchange
            with open(EXCHANGE_FILE, "a") as ef:
                ef.write(json.dumps(payload) + "\n")
                
            # Stream directly to S3 Vault
            upload_to_s3(payload, incident_id)
