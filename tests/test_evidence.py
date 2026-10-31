from core.engine import SecurityEventEngine
from core.evidence import EvidenceEngine
from core.schemas import SecurityEvent
from uuid import uuid4
import pytest


def create_test_event():
    return SecurityEvent(
        event_type="unauthorized_tool_call",
        category="agent",
        source="finance-agent",
        target="database-tool",
    )


def test_collect_evidence():
    event = create_test_event()
    engine = EvidenceEngine()

    record = engine.collect(
        event,
        description="Unauthorized database access detected",
    )

    assert record.event_id == event.event_id
    assert record.source == event.source


def test_retrieve_event_evidence():
    event = create_test_event()
    engine = EvidenceEngine()

    engine.collect(event, "Evidence 1")
    engine.collect(event, "Evidence 2")

    records = engine.get_event_evidence(event.event_id)

    assert len(records) == 2


def test_retrieve_evidence_by_id():
    event = create_test_event()
    engine = EvidenceEngine()

    record = engine.collect(event, "Suspicious activity")

    assert engine.get_evidence(record.evidence_id) == record


def test_duplicate_evidence_id_is_rejected_with_controlled_factory():
    event = create_test_event()
    fixed_id = uuid4()
    engine = EvidenceEngine(evidence_id_factory=lambda: fixed_id)

    engine.collect(event, "First record")

    with pytest.raises(ValueError, match="Duplicate evidence ID"):
        engine.collect(event, "Second record")


def test_event_evidence_is_scoped_to_its_event():
    first_event = create_test_event()
    second_event = SecurityEvent(event_type="port_scan", category="network", source="sensor-b")
    engine = EvidenceEngine()

    first_record = engine.collect(first_event, "First event evidence")
    second_record = engine.collect(second_event, "Second event evidence")

    assert engine.get_event_evidence(first_event.event_id) == [first_record]
    assert engine.get_event_evidence(second_event.event_id) == [second_record]
    assert first_record.collected_at.tzinfo is not None
