from uuid import UUID, uuid4
from datetime import datetime, timezone
from typing import Any, Callable

from pydantic import BaseModel, Field

from core.schemas import EvidenceProvenance, SecurityEvent


class EvidenceRecord(BaseModel):
    evidence_id: UUID = Field(default_factory=uuid4)
    event_id: UUID
    description: str
    source: str
    provenance: EvidenceProvenance = EvidenceProvenance.ACTUAL_COLLECTED
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    details: dict[str, Any] = Field(default_factory=dict)


class EvidenceEngine:
    """In-memory, event-scoped evidence store with provenance tracking.

    Current limitations:
    - Records are held in memory inside the central engine and are lost on
      service restart until persistent storage (Member C) is integrated.
    - Unknown event or evidence IDs return None / empty results instead of
      raising, because evidence can legitimately be queried across sessions.
    - Synthetic fixture evidence is never promoted to actual collected
      evidence; user-supplied evidence remains separately identifiable via its
      provenance.
    """

    def __init__(self, evidence_id_factory: Callable[[], UUID] = uuid4):
        self.records: dict[UUID, EvidenceRecord] = {}
        self._evidence_id_factory = evidence_id_factory

    def collect(
        self,
        event: SecurityEvent,
        description: str,
        details: dict[str, Any] | None = None,
        *,
        source: str | None = None,
        provenance: EvidenceProvenance = EvidenceProvenance.ACTUAL_COLLECTED,
    ) -> EvidenceRecord:
        if provenance == EvidenceProvenance.ACTUAL_COLLECTED and (
            source is None
        ):
            source = event.source

        record = EvidenceRecord(
            evidence_id=self._evidence_id_factory(),
            event_id=event.event_id,
            description=description,
            source=source or event.source,
            provenance=provenance,
            details=details or {},
        )

        if record.evidence_id in self.records:
            raise ValueError(f"Duplicate evidence ID: {record.evidence_id}")

        self.records[record.evidence_id] = record
        return record

    def get_evidence(self, evidence_id: UUID) -> EvidenceRecord | None:
        return self.records.get(evidence_id)

    def get_event_evidence(self, event_id: UUID) -> list[EvidenceRecord]:
        return [
            record
            for record in self.records.values()
            if record.event_id == event_id
        ]

    def list_evidence(self) -> list[EvidenceRecord]:
        return list(self.records.values())
