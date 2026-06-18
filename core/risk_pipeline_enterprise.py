import csv
import json
import os
import time
from datetime import datetime

# CONFIGURATION PARAMETERS
EXCHANGE_FILE_PATH = "telemetry_exchange.json"
OUTPUT_REGISTER_PATH = "enterprise_risk_register.csv"

# Mock Asset Inventory defining business criticality
ASSET_CRITICALITY_MAP = {
    "Prod_Payment_Gateway": "High",
    "Customer_Auth_DB": "High",
    "Corporate_Email_Server": "Medium",
    "Internal_HR_Portal": "Medium",
    "Dev_Sandbox_Environment": "Low"
}

class RiskRegisterPipeline:
    def __init__(self):
        print("[*] Initializing Full-Spectrum Risk & Vulnerability Management Pipeline...")
        print(f"[*] Ingestion Engine Active -> Monitoring {EXCHANGE_FILE_PATH} for telemetry slates.")
        self.initialize_csv_headers()

    def initialize_csv_headers(self):
        """Ensures the enterprise register exists and has proper audit column slates."""
        headers = [
            "Risk_ID", "Timestamp_UTC", "Asset_Name", "Asset_Criticality", 
            "Attack_Vector", "MITRE_ID", "Firewall_Posture", "IAM_Status",
            "CVSS_Base_Score", "Inherent_Risk_Score", "Inherent_Risk_Rating", 
            "Annualized_Loss_Expectancy", "SOX_404_Status", "NIST_Control_Mapping"
        ]
        if not os.path.exists(OUTPUT_REGISTER_PATH):
            with open(OUTPUT_REGISTER_PATH, mode="w", newline="", encoding="utf-8") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(headers)

    def calculate_inherent_risk(self, cvss_score, criticality, firewall_posture):
        """Calculates risk ratings using quantitative FAIR escalation logic."""
        weight_map = {"High": 3, "Medium": 2, "Low": 1}
        weight = weight_map.get(criticality, 1)
        
        # Core Risk Formula: CVSS Base * Asset Weight
        risk_score = round(cvss_score * weight, 1)
        
        # CONTINUOUS AUDIT ESCALATION (FAIR FACTOR):
        # If the control validation demonstrates a degraded local firewall posture, 
        # escalate the risk score by an institutional multiplier (15%) due to vulnerability compounding.
        if firewall_posture == "Degraded":
            risk_score = round(risk_score * 1.15, 1)
            
        # Categorize final rating based on matrix thresholds
        if risk_score >= 22.1:
            rating = "CRITICAL"
        elif risk_score >= 15.1:
            rating = "HIGH"
        elif risk_score >= 7.1:
            rating = "MEDIUM"
        else:
            rating = "LOW"
            
        return risk_score, rating

    def process_telemetry_payload(self, raw_line):
        """Parses a single JSON line through the multi-layer calculation engine."""
        try:
            payload = json.loads(raw_line.strip())
            
            # Layer 1: Telemetry Parsing
            meta = payload["telemetry_metadata"]
            incident = payload["security_incident_details"]
            audit = payload["continuous_control_audit"]
            identity = payload["identity_context"]
            
            asset = meta["origin_host"]
            cvss = incident["raw_cvss_base_score"]
            vector = incident["attack_vector"]
            firewall = audit["firewall_posture"]
            
            # Layer 2 & 3: Contextual & Identity Enrichment
            criticality = ASSET_CRITICALITY_MAP.get(asset, "Low")
            
            # Layer 4: Quantitative FAIR Risk Calculations
            risk_score, risk_rating = self.calculate_inherent_risk(cvss, criticality, firewall)
            
            # Quantitative Loss Metric: Risk Score * $10,000 baseline loss expectancy multiplier
            annualized_loss_expectancy = f"${int(risk_score * 10000):,}"
            
            # Layer 5: Compliance Mapping Generation
            sox_status = "FAIL" if firewall == "Degraded" else "PASS"
            nist_mapping = "PR.PT-4 (Network Boundary)" if vector == "SSH Brute Force" else "PR.AC-1 (Access Control)"
            
            # Assemble the structured record matching our column template
            risk_record = [
                meta["event_id"],
                meta["timestamp_utc"],
                asset,
                criticality,
                vector,
                incident["mitre_attack_id"],
                firewall,
                identity["iam_status"],
                cvss,
                risk_score,
                risk_rating,
                annualized_loss_expectancy,
                sox_status,
                nist_mapping
            ]
            
            self.append_to_register(risk_record)
            print(f"[PIPELINE SUCCESS] Processed event {meta['event_id']} -> Rating: {risk_rating} | ALE: {annualized_loss_expectancy}")
            
        except Exception as e:
            print(f"[PIPELINE ERROR] Failed to process incoming telemetry payload: {e}")

    def append_to_register(self, record_row):
        """Appends the finalized audit row immediately into the enterprise CSV asset."""
        try:
            with open(OUTPUT_REGISTER_PATH, mode="a", newline="", encoding="utf-8") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(record_row)
        except IOError as e:
            print(f"[STORAGE ERROR] Unable to write row item to risk ledger disk: {e}")

    def monitor_stream(self):
        """Main active loop tracking line appends inside the telemetry interface file."""
        # Create exchange pipeline if it doesn't exist yet to prevent file read errors
        if not os.path.exists(EXCHANGE_FILE_PATH):
            open(EXCHANGE_FILE_PATH, 'w').close()
            
        with open(EXCHANGE_FILE_PATH, "r") as exchange_file:
            # Shift file pointer directly to the current end of file to wait for fresh appends
            exchange_file.seek(0, os.SEEK_END)
            
            try:
                while True:
                    line = exchange_file.readline()
                    if not line:
                        time.sleep(0.5)  # Idle polling interval to conserve system resources
                        continue
                    self.process_telemetry_payload(line)
            except KeyboardInterrupt:
                print("\n[*] Risk Register Pipeline execution safely terminated.")

if __name__ == "__main__":
    pipeline = RiskRegisterPipeline()
    pipeline.monitor_stream()
