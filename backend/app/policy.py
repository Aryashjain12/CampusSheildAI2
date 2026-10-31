from app.models import ActionResult, Incident
from app import store

ALLOWED_DEMO_ACTIONS = {"simulated_quarantine"}


def respond(incident: Incident) -> ActionResult:
    """Simulate containment only; never changes the real host/network."""
    if incident.status in {"contained", "resolved"}:
        return ActionResult(
            incident_id=incident.id,
            action="simulated_quarantine",
            status="rejected",
            message="Incident is already contained or resolved.",
        )

    if incident.severity not in {"high", "critical"}:
        return ActionResult(
            incident_id=incident.id,
            action="simulated_quarantine",
            status="rejected",
            message="Policy requires high or critical severity for this demo action.",
        )

    action = "simulated_quarantine"
    if action not in ALLOWED_DEMO_ACTIONS:
        return ActionResult(
            incident_id=incident.id,
            action=action,
            status="rejected",
            message="Action is not allowlisted.",
        )

    store.SIMULATED_QUARANTINE.add(incident.source_id)
    incident.status = "contained"
    incident.response_action = action
    store.audit("response_simulated", incident.id, f"{action} applied to {incident.source_id}")
    return ActionResult(
        incident_id=incident.id,
        action=action,
        status="simulated",
        message=f"Simulated quarantine applied to {incident.source_id}; no real network was changed.",
    )


def verify(incident: Incident) -> dict:
    """Verify simulator state; this is not a real network reachability test."""
    contained = incident.source_id in store.SIMULATED_QUARANTINE
    if contained:
        incident.verification = "passed"
        incident.status = "resolved"
        message = "Verification passed: source is present in simulated quarantine state."
    else:
        incident.verification = "failed"
        incident.status = "escalated"
        message = "Verification failed: source is not present in simulated quarantine state."
    store.audit("verification", incident.id, message)
    return {"incident_id": incident.id, "passed": contained, "message": message}
