from app.models import Incident

INCIDENTS: dict[str, Incident] = {}
AUDIT: list[dict] = []
SIMULATED_QUARANTINE: set[str] = set()
INVESTIGATIONS: dict[str, object] = {}


def audit(action: str, incident_id: str | None, details: str) -> None:
    from datetime import datetime, timezone
    AUDIT.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "incident_id": incident_id,
        "details": details,
    })
