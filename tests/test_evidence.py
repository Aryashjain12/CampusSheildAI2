from core.engine import SecurityEventEngine
from core.evidence import EvidenceEngine
from core.schemas import SecurityEvent


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
