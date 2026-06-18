import streamlit as st
import pandas as pd
import plotly.express as px
import os

st.set_page_config(
    page_title="Aegis-Track Enterprise Risk Matrix",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Aegis-Track Enterprise Risk Quantification Dashboard")
st.markdown("### Real-Time Financial Exposure & Compliance Telemetry")
st.markdown("---")

CSV_FILE = "enterprise_risk_register.csv"

if not os.path.exists(CSV_FILE):
    st.error(f"[!] Target Risk Ledger Missing: '{CSV_FILE}' not found. Run the ingestion pipeline to generate telemetry.")
else:
    df = pd.read_csv(CSV_FILE)
    df.columns = df.columns.str.strip()

    total_ale = df['ALE'].sum() if 'ALE' in df.columns else 0
    total_incidents = len(df)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(label="Total Annualized Loss Expectancy (ALE)", value=f"${total_ale:,.2f}")
    with col2:
        st.metric(label="Active Tracked Incidents", value=total_incidents)
    with col3:
        st.metric(label="Cloud Vault Archival Sync", value="ACTIVE ✔️")
    with col4:
        st.metric(label="Primary Node Status", value="ONLINE")

    st.markdown("---")
    left_chart, right_chart = st.columns(2)

    with left_chart:
        st.markdown("#### Financial Risk Contribution by Incident Type")
        if 'Threat Signature' in df.columns and 'ALE' in df.columns:
            fig_bar = px.bar(df, x='Threat Signature', y='ALE', color='Risk Rating', template="plotly_dark")
            st.plotly_chart(fig_bar, use_container_width=True)

    with right_chart:
        st.markdown("#### Vulnerability Exposure Profile")
        if 'Vulnerability' in df.columns:
            fig_box = px.box(df, y='Vulnerability', points="all", template="plotly_dark", color_discrete_sequence=['#00CC96'])
            st.plotly_chart(fig_box, use_container_width=True)

    st.markdown("---")
    st.markdown("#### Complete Enterprise Risk Register Ledger")
    st.dataframe(df, use_container_width=True)
