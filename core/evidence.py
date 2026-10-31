from uuid import UUID, uuid4
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from core.schemas import SecurityEvent


class EvidenceRecord(BaseModel):
    evidence_id: UUID = Field(default_factory=uuid4)
    event_id: UUID
    description: str
    source: str
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    details: dict[str, Any] = Field(default_factory=dict)


class EvidenceEngine:
    def __init__(self):
        self.records: dict[UUID, EvidenceRecord] = {}

    def collect(
        self,
        event: SecurityEvent,
        description: str,
        details: dict[str, Any] | None = None,
    ) -> EvidenceRecord:

        record = EvidenceRecord(
            event_id=event.event_id,
            description=description,
            source=event.source,
            details=details or {},
        )

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
