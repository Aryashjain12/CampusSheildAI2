from uuid import uuid4
from app.models import NetworkEvent, Incident


def detect(event: NetworkEvent) -> Incident | None:
    """Small deterministic starter detector; not a production IDS."""
    if event.event_type == "port_scan":
        ports = event.features.get("unique_destination_ports", 0)
        connections = event.features.get("connection_attempts", 0)
        if not isinstance(ports, (int, float)) or not isinstance(connections, (int, float)):
            return None
        if ports >= 12 and connections >= 20:
            return Incident(
                id=str(uuid4()),
                event_type=event.event_type,
                source_id=event.source_id,
                severity="high",
                risk_score=85,
                title="Possible port scanning detected",
                evidence=[
                    f"{int(ports)} unique destination ports observed",
                    f"{int(connections)} connection attempts observed",
                    "Threshold-based demo rule matched",
                ],
            )
    elif event.event_type == "brute_force":
        failures = event.features.get("failed_logins", 0)
        if isinstance(failures, (int, float)) and failures >= 8:
            return Incident(
                id=str(uuid4()),
                event_type=event.event_type,
                source_id=event.source_id,
                severity="high",
                risk_score=82,
                title="Repeated authentication failures detected",
                evidence=[
                    f"{int(failures)} failed login attempts observed",
                    "Threshold-based demo rule matched",
                ],
            )
    return None
