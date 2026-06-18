# 🛡️ Aegis-Enterprise Threat Telemetry & Risk Quantification Pipeline

An enterprise-grade, out-of-band Micro-SIEM and algorithmic risk quantification pipeline. This architecture ingest real-time Linux host log anomalies, streams immutable audit data to AWS S3 storage vaults, and programmatically processes security events into financial risk metrics utilizing the **Factor Analysis of Information Risk (FAIR)** methodology mapped to **NIST SP 800-53** controls.

---

## 🏗️ System Architecture & Data Flow

1. **Log Ingestion & Threat Detection:** An active host agent tails local authentication subsystems (`/var/log/secure`), parsing high-velocity anomalies via cryptographic signature matching.
2. **Out-of-Band Cloud Archival:** Triggered incidents bypass standard local retention, streaming instantly as structured JSON payloads to an immutable AWS S3 Vault via `boto3`.
3. **FAIR Quantification Engine:** Raw telemetry is ingested by a data pipeline that calculates Single Loss Expectancy (SLE) and Annualized Loss Expectancy (ALE) using asset values and threat frequencies.
4. **Compliance Mapping:** Vulnerabilities are programmatically categorized against NIST SP 800-53 (AU-6 Log Review, Analysis, and Reporting) configurations.
5. **Executive Telemetry Interface:** A responsive Streamlit web application compiles backend ledger state arrays into multi-variant interactive Plotly financial risk profiles.

---

## 📂 Repository Structure

```text
Aegis-Enterprise-Pipeline/
├── README.md                      # Technical documentation & architecture specs
├── requirements.txt               # System dependency manifests
├── core/
│   ├── aegis_track_enterprise.py # Real-time log monitoring & AWS streaming engine
│   └── risk_pipeline.py           # NIST-mapped FAIR quantification compiler
└── interface/
    └── dashboard.py               # Streamlit analytics front-end
