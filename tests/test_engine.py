from core.engine import SecurityEventEngine
from core.schemas import SecurityEvent


def create_test_event():
    return SecurityEvent(
        event_type="port_scan",
        category="network",
        source="192.168.1.10",
    )


def test_engine_stores_event():
    engine = SecurityEventEngine()
    event = create_test_event()

    engine.ingest(event)

    assert len(engine.list_events()) == 1


def test_engine_retrieves_event():
    engine = SecurityEventEngine()
    event = create_test_event()

    engine.ingest(event)

    assert engine.get_event(event.event_id) == event


def test_engine_rejects_duplicate_event():
    engine = SecurityEventEngine()
    event = create_test_event()

    engine.ingest(event)

    try:
        engine.ingest(event)
        assert False, "Duplicate event should be rejected"
    except ValueError:
        pass

def test_engine_collects_evidence():
    engine = SecurityEventEngine()
    event = create_test_event()

    engine.ingest(event)

    evidence = engine.collect_evidence(
        event.event_id,
        "Unauthorized network activity detected",
    )

    assert evidence.event_id == event.event_id
    assert len(engine.evidence_engine.list_evidence()) == 1

def test_engine_investigates_event():
    engine = SecurityEventEngine()

    event = SecurityEvent(
        event_type="port_scan",
        category="network",
        source="192.168.1.10",
        target="campus-lab-service",
        severity="high",
    )

    engine.ingest(event)

    result = engine.investigate(event.event_id)

    assert result.verdict is not None
    assert result.confidence is not None
    assert len(result.steps) > 0
