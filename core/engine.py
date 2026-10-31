from uuid import UUID

from core.schemas import SecurityEvent
from core.evidence import EvidenceEngine, EvidenceRecord
from core.socrates_adapter import investigate_event


class SecurityEventEngine:
    def __init__(self):
        self.events: dict[UUID, SecurityEvent] = {}
        self.evidence_engine = EvidenceEngine()

    def ingest(self, event: SecurityEvent) -> SecurityEvent:
        if event.event_id in self.events:
            raise ValueError(f"Duplicate event ID: {event.event_id}")

        self.events[event.event_id] = event
        return event

    def investigate(self, event_id: UUID):
        event = self.get_event(event_id)

        if event is None:
            raise ValueError("Event not found")

        return investigate_event(event)

    def collect_evidence(
        self,
        event_id: UUID,
        description: str,
        details: dict | None = None,
    ) -> EvidenceRecord:
        event = self.get_event(event_id)

        if event is None:
            raise ValueError("Event not found")

        return self.evidence_engine.collect(event, description, details)

    def get_event(self, event_id: UUID) -> SecurityEvent | None:
        return self.events.get(event_id)

    def list_events(self) -> list[SecurityEvent]:
        return list(self.events.values())
