from datetime import datetime
from uuid import UUID

from core.schemas import EventCategory, EventCorrelation, SecurityEvent, Severity
from core.evidence import EvidenceEngine, EvidenceRecord
from core.socrates_adapter import investigate_event
from core.schemas import NormalizedInvestigationResult


class SecurityEventEngine:
    def __init__(self):
        self.events: dict[UUID, SecurityEvent] = {}
        self.evidence_engine = EvidenceEngine()
        self.investigations: dict[UUID, NormalizedInvestigationResult] = {}
        self.correlations: list[EventCorrelation] = []
        self.correlation_window_seconds = 15 * 60

    def ingest(self, event: SecurityEvent) -> SecurityEvent:
        if event.event_id in self.events:
            raise ValueError(f"Duplicate event ID: {event.event_id}")

        self.events[event.event_id] = event
        self._correlate(event)
        return event

    def investigate(self, event_id: UUID):
        event = self.get_event(event_id)

        if event is None:
            raise ValueError("Event not found")

        result = investigate_event(
            event,
            self.evidence_engine.get_event_evidence(event.event_id),
        )
        self.investigations[event_id] = result
        return result

    def collect_evidence(
        self,
        event_id: UUID,
        description: str,
        details: dict | None = None,
        *,
        source: str | None = None,
        provenance=None,
    ) -> EvidenceRecord:
        event = self.get_event(event_id)

        if event is None:
            raise ValueError("Event not found")

        collect_args = {"source": source} if source else {}
        if provenance is not None:
            collect_args["provenance"] = provenance
        return self.evidence_engine.collect(event, description, details, **collect_args)

    def get_event(self, event_id: UUID) -> SecurityEvent | None:
        return self.events.get(event_id)

    def list_events(
        self,
        *,
        category: EventCategory | None = None,
        severity: Severity | None = None,
        source: str | None = None,
        event_type: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[SecurityEvent]:
        events = self.events.values()
        filtered = [
            event for event in events
            if (category is None or event.category == category)
            and (severity is None or event.severity == severity)
            and (source is None or event.source == source)
            and (event_type is None or event.event_type == event_type)
            and (since is None or event.timestamp >= since)
            and (until is None or event.timestamp <= until)
        ]
        return sorted(filtered, key=lambda event: event.timestamp, reverse=True)

    def get_investigation(self, event_id: UUID) -> NormalizedInvestigationResult | None:
        return self.investigations.get(event_id)

    def list_correlations(self) -> list[EventCorrelation]:
        return list(self.correlations)

    @staticmethod
    def _entity_references(event: SecurityEvent) -> set[str]:
        references = {value for value in (event.source, event.target) if value}
        for container in (event.attributes, event.metadata):
            values = container.get("entity_references", [])
            if isinstance(values, list):
                references.update(value for value in values if isinstance(value, str) and value)
        return references

    def _correlate(self, event: SecurityEvent) -> None:
        """Create only deterministic, cross-category, entity/time correlations."""
        current_entities = self._entity_references(event)
        if not current_entities:
            return
        for other in self.events.values():
            if other.event_id == event.event_id or other.category == event.category:
                continue
            shared = sorted(current_entities & self._entity_references(other))
            if not shared:
                continue
            seconds = abs((event.timestamp - other.timestamp).total_seconds())
            if seconds > self.correlation_window_seconds:
                continue
            ids = sorted((event.event_id, other.event_id), key=str)
            if any(set(correlation.event_ids) == set(ids) for correlation in self.correlations):
                continue
            self.correlations.append(EventCorrelation(
                event_ids=ids,
                shared_entities=shared,
                time_delta_seconds=seconds,
                reason=(
                    f"Cross-category events share entity reference(s): {', '.join(shared)} "
                    f"within the configured {self.correlation_window_seconds}-second window."
                ),
            ))
