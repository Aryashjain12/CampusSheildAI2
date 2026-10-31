import sys
from pathlib import Path

ROOT_PATH = Path(__file__).resolve().parents[2]
if str(ROOT_PATH) not in sys.path:
    sys.path.insert(0, str(ROOT_PATH))

from datetime import datetime
from uuid import UUID

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from app import detection, models, policy, store
from app.models import Incident

from agent.controller import investigate as socrates_investigate
from agent.controller import reconsider as socrates_reconsider

from core.schemas import (
    EvidenceSubmission,
    EventCategory,
    EvidenceProvenance,
    SecurityEvent,
    Severity,
    NormalizedInvestigationResult,
)
from core.engine import SecurityEventEngine
from core.verification import VerificationEngine
from pydantic import BaseModel

security_engine = SecurityEventEngine()
verification_engine = VerificationEngine()
security_verifications: dict[UUID, dict] = {}

app = FastAPI(
    title="CampusShield AI",
    version="0.1.0",
    description="Safe MVP: deterministic detection and simulated response. No real traffic is blocked.",
)


# Central intelligence dashboard aliases (safe MVP; simulated).
central_sec_engine = security_engine
central_verification_engine = verification_engine
central_security_verifications = security_verifications


# Optional NVIDIA Nemotron advisory controller.
_nemotron_enabled = False


def enable_nemotron_advisory():
    global _nemotron_enabled
    _nemotron_enabled = True


def get_nemotron_status() -> dict:
    from tools.llm_reasoner import is_nemotron_advisory_enabled
    return {
        "enabled": is_nemotron_advisory_enabled(),
        "provider": "nvidia_nemotron",
        "model": "nvidia/nemotron-3.5-lightning-30b-a3b",
        "base_url": "https://integrate.api.nvidia.com/v1",
    }


print("INFO: Optional NVIDIA Nemotron advisory controller loaded.")


def get_advisory_schema() -> type[BaseModel]:
    from tools.llm_reasoner import get_advisory_schema
    return get_advisory_schema()


__all__ = [
    "app",
    "security_engine",
    "verification_engine",
    "security_verifications",
    "central_sec_engine",
    "central_verification_engine",
    "central_security_verifications",
    "ingest_security_event",
    "list_security_events",
    "get_security_event",
    "collect_security_event_evidence",
    "get_security_event_evidence",
    "list_evidence",
    "investigate_security_event",
    "get_security_event_investigation",
    "verify_security_event",
    "get_security_event_verification",
    "list_correlations",
    "get_system_status",
    "get_system_modules",
    "get_nemotron_status",
    "get_advisory_schema",
]


def _resolve_incident_class():
    return Incident


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "service": "campusshield-ai", "version": "0.1.0"}


@app.post("/events", response_model=Incident | dict)
def ingest_event(event: models.NetworkEvent):
    incident = detection.detect(event)
    if incident is None:
        store.audit("event_ingested_no_alert", None, f"{event.event_type} from {event.source_id}")
        return {"accepted": True, "alert": False, "message": "Event ingested; no demo rule matched."}
    # Link every detector alert to the SOCrates-style evidence investigation.
    host = event.destination_id
    if host not in {"campus-lab-service", "campus-lab-login", "campus-database-01", "campus-decommissioned-01"}:
        host = "campus-lab-service" if event.event_type == "port_scan" else "campus-lab-login"
    severity = incident.severity.title()
    investigation = socrates_investigate({
        "alert_id": f"CS-{incident.id[:8]}", "timestamp": event.timestamp.isoformat(),
        "signature": incident.title, "severity": severity,
        "source_ip": event.source_id, "dest_host": host,
        "description": f"Synthetic CampusShield event: {event.event_type}; features={event.features}"
    })
    store.INVESTIGATIONS[incident.id] = investigation
    _sync_investigation(incident, investigation)
    store.INCIDENTS[incident.id] = incident
    store.audit("incident_created", incident.id, incident.title)
    store.audit("investigation_completed", incident.id, f"SOCrates verdict: {investigation.verdict}")

    Incident = _resolve_incident_class()
    return Incident(**incident.__dict__) if hasattr(incident, '__dict__') else incident


@app.post("/demo/port-scan", response_model=Incident)
def demo_port_scan():
    event = models.NetworkEvent(
        event_type="port_scan",
        source_id="demo-host-17",
        destination_id="campus-lab-service",
        features={"unique_destination_ports": 24, "connection_attempts": 61},
    )
    incident = detection.detect(event)
    if incident is None:
        raise HTTPException(status_code=500, detail="Demo event did not trigger expected detection.")
    investigation = socrates_investigate({"alert_id": f"CS-{incident.id[:8]}", "timestamp": incident.created_at.isoformat(),
        "signature": incident.title, "severity": incident.severity.title(), "source_ip": incident.source_id,
        "dest_host": "campus-lab-service", "description": "Synthetic port-scan demo event."})
    store.INVESTIGATIONS[incident.id] = investigation
    _sync_investigation(incident, investigation)
    store.INCIDENTS[incident.id] = incident
    store.audit("demo_port_scan", incident.id, "Synthetic demo event generated")
    store.audit("incident_created", incident.id, incident.title)
    store.audit("investigation_completed", incident.id, f"SOCrates verdict: {investigation.verdict}")

    Incident = _resolve_incident_class()
    return Incident(**incident.__dict__) if hasattr(incident, '__dict__') else incident


@app.post("/demo/brute-force", response_model=Incident)
def demo_brute_force():
    event = models.NetworkEvent(
        event_type="brute_force",
        source_id="demo-auth-client-04",
        destination_id="campus-lab-login",
        features={"failed_logins": 14},
    )
    incident = detection.detect(event)
    if incident is None:
        raise HTTPException(status_code=500, detail="Demo event did not trigger expected detection.")
    investigation = socrates_investigate({"alert_id": f"CS-{incident.id[:8]}", "timestamp": incident.created_at.isoformat(),
        "signature": incident.title, "severity": incident.severity.title(), "source_ip": incident.source_id,
        "dest_host": "campus-lab-login", "description": "Synthetic brute-force demo event."})
    store.INVESTIGATIONS[incident.id] = investigation
    _sync_investigation(incident, investigation)
    store.INCIDENTS[incident.id] = incident
    store.audit("demo_brute_force", incident.id, "Synthetic demo event generated")
    store.audit("incident_created", incident.id, incident.title)
    store.audit("investigation_completed", incident.id, f"SOCrates verdict: {investigation.verdict}")

    Incident = _resolve_incident_class()
    return Incident(**incident.__dict__) if hasattr(incident, '__dict__') else incident


def _incident_ok(incident):
    return incident is not None


@app.get("/incidents", response_model=list[Incident])
def list_incidents():
    return sorted(store.INCIDENTS.values(), key=lambda x: x.created_at, reverse=True)


@app.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str):
    incident = store.INCIDENTS.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident


@app.post("/incidents/{incident_id}/respond")
def respond_to_incident(incident_id: str):
    incident = store.INCIDENTS.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    result = policy.respond(incident)
    return result


@app.post("/incidents/{incident_id}/verify")
def verify_incident(incident_id: str):
    incident = store.INCIDENTS.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return policy.verify(incident)


@app.get("/incidents/{incident_id}/investigation")
def get_investigation(incident_id: str):
    investigation = store.INVESTIGATIONS.get(incident_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return investigation.summary()


@app.post("/incidents/{incident_id}/reconsider")
def reconsider_incident(incident_id: str, payload: dict):
    incident = store.INCIDENTS.get(incident_id)
    investigation = store.INVESTIGATIONS.get(incident_id)
    if incident is None or investigation is None:
        raise HTTPException(status_code=404, detail="Incident or investigation not found.")
    note = str(payload.get("note", "")).strip()
    if not note or len(note) > 500:
        raise HTTPException(status_code=422, detail="Provide a note of 1–500 characters.")
    from datetime import datetime, timezone
    override = {"alert_id": investigation.alert["alert_id"], "note": note,
                "received_at": datetime.now(timezone.utc).isoformat()}
    start, end = payload.get("claimed_window_start"), payload.get("claimed_window_end")
    if start and end:
        override["claimed_window_start"], override["claimed_window_end"] = str(start), str(end)
    socrates_reconsider(investigation, override=override)
    _sync_investigation(incident, investigation)
    store.audit("investigation_reconsidered", incident.id, f"Updated verdict: {investigation.verdict}")
    return investigation.summary()


def _sync_investigation(incident, investigation):
    incident.investigation = investigation.summary()
    incident.verdict = investigation.verdict
    incident.confidence = investigation.confidence
    incident.reasoning = investigation.reasoning
    incident.action_history = list(investigation.actions_taken)
    incident.evidence = list(incident.evidence) + [f"SOCrates verdict: {investigation.verdict} ({investigation.confidence} confidence)"]
    incident.evidence.extend(f"{step['label']}: {step['detail']}" for step in investigation.steps if step["label"] in {"DECISION", "REASONING", "REASONING (AI)", "SELF-CHECK"})
    if investigation.verdict in {"confirmed_breach", "data_integrity_anomaly", "suspicious_repeat_actor", "override_disputed"}:
        incident.status = "escalated"
    if investigation.actions_taken:
        incident.response_action = "simulated_source_block" if any(a.get("action")=="block" for a in investigation.actions_taken) else "simulated_source_unblock"
        if "firewall_check_after_override" in investigation.evidence:
            incident.verification = "passed" if investigation.evidence["firewall_check_after_override"] is False else "failed"
        elif "firewall_check" in investigation.evidence:
            incident.verification = "passed" if investigation.evidence["firewall_check"] is True else "failed"


@app.get("/audit")
def get_audit():
    return list(reversed(store.AUDIT))


# --- Member B: Multi-Agent Network, Attack Scenarios & Evaluation Endpoints ---

@app.post("/demo/agent-attack")
def demo_agent_attack():
    from agent_network.attacks.run_main_story import run_main_attack_story
    import uuid
    result = run_main_attack_story()

    # Register as Incident in dashboard store
    inc_id = f"inc_{uuid.uuid4().hex[:8]}"
    incident = Incident(
        id=inc_id,
        event_type="agent_hijack_and_spread",
        source_id="198.51.100.44",
        severity="critical",
        risk_score=96,
        title=f"Multi-Agent Compromise: {result['spread_strip']}",
        evidence=[
            f"Patient zero identified: {result['patient_zero']}",
            f"Spread strip: {result['spread_strip']}",
            f"Records exposed: {', '.join(result['records_exposed'])}",
            f"Records exfiltrated (provable via canary): {', '.join(result['records_exfiltrated'])}",
            f"Emitted {result['events_count']} CommonEvents into audit bus"
        ],
        status="escalated",
        verdict="confirmed_agent_breach",
        confidence="0.98",
        reasoning=f"Helpdesk was hijacked via indirect prompt injection in a support ticket, propagating unauthorized commands to Finance agent. Library remained clean.",
        response_action="revoke_agent_tools_and_quarantine_memory"
    )
    store.INCIDENTS[inc_id] = incident
    store.audit("demo_agent_attack", inc_id, f"Executed main attack: {result['spread_strip']}")
    store.audit("patient_zero_flagged", inc_id, f"Patient Zero: {result['patient_zero']}")
    store.audit("canary_exfiltration_confirmed", inc_id, f"Provable exfiltration of {result['records_exfiltrated']}")
    return {"incident": incident, "attack_summary": result}


@app.get("/api/scenarios")
def get_scenarios(split: str | None = None):
    p = Path(__file__).resolve().parents[1] / "data" / "scenarios_dataset.json"
    if not p.exists():
        from agent_network.scenarios.generator import save_scenarios_dataset
        save_scenarios_dataset(p)
    import json
    data = json.loads(p.read_text(encoding="utf-8"))
    if split:
        data = [s for s in data if s.get("split") == split]
    return {"total": len(data), "scenarios": data}


@app.post("/api/scenarios/benchmark")
def run_scenarios_benchmark(payload: dict | None = None):
    from agent_network.scenarios.runner import run_benchmark, ScenarioRunner
    from agent_network.scenarios.generator import generate_scenarios, FIXED_SEED

    p = payload or {}
    split_filter = p.get("split")
    decoys_enabled = p.get("decoys_enabled", True)

    dataset = generate_scenarios(count=80, seed=FIXED_SEED)
    if split_filter:
        dataset = [s for s in dataset if s.get("split") == split_filter]

    runner = ScenarioRunner(decoys_enabled=decoys_enabled, graph_enabled=True)
    results = [runner.run_scenario(s) for s in dataset]

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    pz_correct = sum(1 for r in results if r["patient_zero_match"])
    states_correct = sum(1 for r in results if r["states_match"])
    decoys_triggered = sum(r["decoys_triggered_count"] for r in results)

    return {
        "total_scenarios": total,
        "passed": passed,
        "pass_rate": round(passed / total, 4) if total > 0 else 0.0,
        "patient_zero_accuracy": round(pz_correct / total, 4) if total > 0 else 0.0,
        "per_agent_state_accuracy": round(states_correct / total, 4) if total > 0 else 0.0,
        "decoys_enabled": decoys_enabled,
        "decoys_triggered_total": decoys_triggered,
        "split_evaluated": split_filter or "all",
        "detailed_results": results
    }


@app.get("/api/agent-network/provenance")
def get_provenance():
    from agent_network.evidence_tools import get_provenance_graph
    return get_provenance_graph()


@app.get("/api/agent-network/permissions")
def get_permissions():
    from agent_network.evidence_tools import list_permissions
    return list_permissions()



# ============================================================
# Unified Security Event API — CampusShield AI 2.0
# ============================================================


@app.post("/api/security-events", status_code=status.HTTP_201_CREATED)
def ingest_security_event(event: SecurityEvent):
    try:
        security_engine.ingest(event)
        investigation = security_engine.investigate(event.event_id)

        return {
            "accepted": True,
            "event": event.model_dump(mode="json"),
            "investigation": investigation.model_dump(mode="json"),
        }

    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/api/security-events")
def list_security_events(
    category: EventCategory | None = None,
    severity: Severity | None = None,
    source: str | None = None,
    event_type: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
):
    if since and until and since > until:
        raise HTTPException(status_code=422, detail="since must be earlier than or equal to until.")
    return [
        event.model_dump(mode="json")
        for event in security_engine.list_events(
            category=category,
            severity=severity,
            source=source,
            event_type=event_type,
            since=since,
            until=until,
        )
    ]


@app.get("/api/security-events/{event_id}")
def get_security_event(event_id: UUID):
    event = security_engine.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Security event not found.")
    return event.model_dump(mode="json")


@app.post("/api/security-events/{event_id}/evidence", status_code=status.HTTP_201_CREATED)
def collect_security_event_evidence(event_id: UUID, submission: EvidenceSubmission):
    try:
        evidence = security_engine.collect_evidence(
            event_id,
            submission.description,
            submission.details,
            source=submission.source,
            provenance=submission.provenance,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return evidence.model_dump(mode="json")


@app.get("/api/security-events/{event_id}/evidence")
def get_security_event_evidence(event_id: UUID):
    if security_engine.get_event(event_id) is None:
        raise HTTPException(status_code=404, detail="Security event not found.")
    return [
        evidence.model_dump(mode="json")
        for evidence in security_engine.evidence_engine.get_event_evidence(event_id)
    ]


@app.get("/api/evidence")
def list_evidence():
    return [evidence.model_dump(mode="json") for evidence in security_engine.evidence_engine.list_evidence()]


@app.post("/api/security-events/{event_id}/investigate")
def investigate_security_event(event_id: UUID):
    try:
        result = security_engine.investigate(event_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return result.model_dump(mode="json")


@app.get("/api/security-events/{event_id}/investigation")
def get_security_event_investigation(event_id: UUID):
    if security_engine.get_event(event_id) is None:
        raise HTTPException(status_code=404, detail="Security event not found.")
    result = security_engine.get_investigation(event_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Investigation has not been run for this event.")
    return result.model_dump(mode="json")


@app.post("/api/security-events/{event_id}/verify")
def verify_security_event(event_id: UUID):
    result = security_engine.get_investigation(event_id)
    if result is None:
        if security_engine.get_event(event_id) is None:
            raise HTTPException(status_code=404, detail="Security event not found.")
        raise HTTPException(status_code=409, detail="Investigate the security event before verification.")
    verification = verification_engine.verify(result)
    payload = {
        "passed": verification.passed,
        "checks": verification.checks,
        "failures": verification.failures,
        "timestamp": verification.timestamp.isoformat(),
        "investigation_reference": str(verification.investigation_reference),
        "response_reference": verification.response_reference,
    }
    security_verifications[event_id] = payload
    return payload


@app.get("/api/security-events/{event_id}/verification")
def get_security_event_verification(event_id: UUID):
    if security_engine.get_event(event_id) is None:
        raise HTTPException(status_code=404, detail="Security event not found.")
    verification = security_verifications.get(event_id)
    if verification is None:
        raise HTTPException(status_code=404, detail="Verification has not been run for this event.")
    return verification


@app.get("/api/correlations")
def list_correlations():
    return [correlation.model_dump(mode="json") for correlation in security_engine.list_correlations()]


@app.get("/api/system/status")
def get_system_status():
    return {
        "status": "ok",
        "storage": "in_memory_session_only",
        "events": len(security_engine.events),
        "evidence": len(security_engine.evidence_engine.records),
        "investigations": len(security_engine.investigations),
        "verifications": len(security_verifications),
        "correlations": len(security_engine.correlations),
        "limitations": ["Central intelligence event, evidence, investigation, and verification records are lost when the service restarts."],
    }


@app.get("/api/system/modules")
def get_system_modules():
    return {
        "modules": [
            {"name": "NetworkShield", "status": "Available", "detail": "Synthetic network detection is available; no live telemetry integration is configured."},
            {"name": "AgentShield", "status": "Available", "detail": "Agent-network controls are available but not yet wired into the central event API."},
            {"name": "MemoryShield", "status": "Not integrated", "detail": "No central event adapter is configured."},
            {"name": "DepGuardX", "status": "Not integrated", "detail": "No central event adapter is configured."},
            {"name": "PulseGuardX", "status": "Not integrated", "detail": "No central event adapter is configured."},
            {"name": "CryptoShield", "status": "Not integrated", "detail": "No central event adapter is configured."},
            {"name": "SOCrates", "status": "Integrated", "detail": "Deterministic local fallback remains available; fixture output is labelled synthetic."},
            {"name": "Central Intelligence Engine", "status": "Integrated", "detail": "In-memory session storage; restart does not preserve records."},
        ]
    }
