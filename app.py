
import streamlit as st
from datetime import datetime

# -------------------------------
# 1. PAGE CONFIGURATION
# -------------------------------

st.set_page_config(
    page_title="CampusShield AI 2.0",
    page_icon="🛡️",
    layout="wide"
)

# -------------------------------
# 2. SAMPLE SECURITY ALERTS
# -------------------------------

ALERTS = {
    "Suspicious RCE Attack": {
        "alert_id": "CS-001",
        "source_ip": "198.51.100.23",
        "host": "campus-web-01",
        "severity": "Critical",
        "trusted_source": False,
        "vulnerable": True,
        "exploit_success": True,
        "outbound_data": True,
        "evidence": [
            "Unknown external IP detected",
            "Server has a known vulnerability",
            "Suspicious process execution found",
            "Unexpected outbound data transfer detected"
        ]
    },

    "Authorized Security Scanner": {
        "alert_id": "CS-002",
        "source_ip": "10.0.0.5",
        "host": "campus-web-02",
        "severity": "Medium",
        "trusted_source": True,
        "vulnerable": False,
        "exploit_success": False,
        "outbound_data": False,
        "evidence": [
            "Source IP matches trusted scanner",
            "Scanner is registered as authorized",
            "No successful exploitation evidence"
        ]
    },

    "Attack Attempt Contained": {
        "alert_id": "CS-003",
        "source_ip": "203.0.113.45",
        "host": "campus-app-03",
        "severity": "High",
        "trusted_source": False,
        "vulnerable": True,
        "exploit_success": False,
        "outbound_data": False,
        "evidence": [
            "External suspicious IP detected",
            "Vulnerable software identified",
            "Exploit attempt detected",
            "Security control stopped the process"
        ]
    }
}


# -------------------------------
# 3. INVESTIGATION ENGINE
# -------------------------------

def investigate(alert):

    steps = []

    steps.append("Security alert received")
    steps.append("Checking source IP and asset information")

    if alert["trusted_source"]:
        verdict = "authorized_activity"
        confidence = "High"
        action = "No blocking required"

        steps.append("Source verified as trusted")
        steps.append("Investigation completed")

    elif alert["exploit_success"] and alert["outbound_data"]:
        verdict = "confirmed_breach"
        confidence = "High"
        action = "SIMULATED: Block suspicious IP"

        steps.append("Vulnerability and exploitation evidence found")
        steps.append("Unauthorized outbound activity detected")
        steps.append("Simulated response recommended")

    elif alert["vulnerable"] and not alert["exploit_success"]:
        verdict = "attempted_and_contained"
        confidence = "Medium"
        action = "No additional block simulated"

        steps.append("Vulnerable software identified")
        steps.append("No successful exploitation evidence found")
        steps.append("Attack appears to have been contained")

    else:
        verdict = "inconclusive"
        confidence = "Low"
        action = "Human review required"

        steps.append("Evidence is insufficient for a firm conclusion")

    return {
        "verdict": verdict,
        "confidence": confidence,
        "action": action,
        "steps": steps,
        "evidence": alert["evidence"]
    }


# -------------------------------
# 4. DASHBOARD INTERFACE
# -------------------------------

st.title("🛡️ CampusShield AI 2.0")
st.caption("Evidence-driven cybersecurity investigation platform")

st.divider()

st.subheader("Security Operations Center")

scenario = st.selectbox(
    "Select a security scenario",
    list(ALERTS.keys())
)

alert = ALERTS[scenario]

col1, col2, col3 = st.columns(3)

col1.metric("Alert ID", alert["alert_id"])
col2.metric("Severity", alert["severity"])
col3.metric("Target Host", alert["host"])

st.write("**Source IP:**", alert["source_ip"])

st.divider()

if st.button("🔍 Investigate Security Alert", type="primary"):

    result = investigate(alert)

    st.session_state["result"] = result
    st.session_state["alert"] = alert
    st.session_state["scenario"] = scenario

if "result" in st.session_state:

    result = st.session_state["result"]
    current_alert = st.session_state["alert"]

    st.subheader("Investigation Results")

    st.write("**Verdict:**", result["verdict"].replace("_", " ").upper())
    st.write("**Confidence:**", result["confidence"])
    st.write("**Recommended Action:**", result["action"])

    st.subheader("Evidence Collected")

    for item in result["evidence"]:
        st.write("✓", item)

    st.subheader("Investigation Timeline")

    for index, step in enumerate(result["steps"], start=1):
        st.write(f"{index}. {step}")

    st.divider()

    report = f"""
CAMPUSSHIELD AI 2.0
SECURITY INVESTIGATION REPORT

Scenario: {st.session_state['scenario']}
Alert ID: {current_alert['alert_id']}
Source IP: {current_alert['source_ip']}
Target Host: {current_alert['host']}
Severity: {current_alert['severity']}

VERDICT: {result['verdict']}
CONFIDENCE: {result['confidence']}
ACTION: {result['action']}

EVIDENCE:
{chr(10).join(result['evidence'])}

INVESTIGATION STEPS:
{chr(10).join(result['steps'])}

Note: This is a prototype using supplied sample data.
Response actions are simulated, not real firewall operations.
"""

    st.download_button(
        "Download Investigation Report",
        data=report,
        file_name="campusshield_report.txt",
        mime="text/plain"
    )

st.divider()

st.caption(
    "CampusShield AI 2.0 | Phase 1 Prototype | "
    "Sample data and simulated response"
)
	
