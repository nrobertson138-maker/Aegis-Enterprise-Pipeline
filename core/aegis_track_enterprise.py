import time
import os
import re
import json
import boto3
from datetime import datetime

LOG_FILE = "/var/log/secure"
EXCHANGE_FILE = "telemetry_exchange.json"
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

with open(LOG_FILE, "r") as f:
    f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue
        
        if "Failed password for root" in line:
            print("[CRITICAL INTERVENTION] Full-spectrum audit alert generated for SSH Brute Force.")
            incident_id = os.urandom(4).hex()
            
            payload = {
                "incident_id": incident_id,
                "timestamp": datetime.now().isoformat(),
                "node": "localhost.localdomain",
                "threat_signature": "SSH Brute Force Attempt",
                "raw_log": line.strip()
            }
            
            # Export to local pipeline exchange
            with open(EXCHANGE_FILE, "w") as ef:
                json.dump(payload, ef, indent=4)
                
            # Stream directly to S3 Vault
            upload_to_s3(payload, incident_id)
