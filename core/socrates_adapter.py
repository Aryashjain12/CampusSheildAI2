import sys
from pathlib import Path

BACKEND_PATH = str(Path(__file__).resolve().parent.parent / "backend")

if BACKEND_PATH not in sys.path:
    sys.path.insert(0, BACKEND_PATH)

from agent.controller import investigate

from core.schemas import SecurityEvent


def investigate_event(event: SecurityEvent):
    alert = {
        "event_id": str(event.event_id),
        "event_type": event.event_type,
        "source_id": event.source,
        "destination_id": event.target,
        "source_ip": event.source,
        "dest_host": event.target,
        "severity": event.severity.value,
        "timestamp": event.timestamp.isoformat(),
        "signature": event.event_type,
    }

    return investigate(alert)
