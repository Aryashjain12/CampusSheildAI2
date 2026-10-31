"""Route-function tests for the additive central intelligence API.

The installed Python 3.14/Starlette TestClient combination hangs before routing,
so request validation remains covered by FastAPI/Pydantic and these tests exercise
the route handlers directly.
"""
import pytest
from fastapi import HTTPException

from app.main import (
    app,
    collect_security_event_evidence,
    get_security_event_verification,
    get_system_status,
    ingest_security_event,
    investigate_security_event,
    list_evidence,
    list_correlations,
    list_security_events,
    security_engine,
    security_verifications,
    verify_security_event,
)
from uuid import UUID
from core.schemas import (
    EvidenceSubmission,
    EventCategory,
    EvidenceProvenance,
    SecurityEvent,
    Severity,
)
from pydantic import ValidationError


def _reset_central_engine():
    security_engine.events.clear()
    security_engine.evidence_engine.records.clear()
    security_engine.investigations.clear()
    security_engine.correlations.clear()
    security_verifications.clear()


def _make_event(category: EventCategory, **kwargs) -> SecurityEvent:
    defaults = {
        "event_type": "test-event",
        "category": category,
        "source": "test-source",
        "target": "test-target",
    }
    defaults.update(kwargs)
    return SecurityEvent(**defaults)


def test_security_event_api_lifecycle_and_filters():
    _reset_central_engine()
    event = SecurityEvent(event_type="suspicious_outbound", category="network", source="198.51.100.9", target="campus-lab-service", severity="high", attributes={"entity_references": ["case-42"]})
    created = ingest_security_event(event)
    event_id = event.event_id
    assert created["accepted"] is True

    with pytest.raises(HTTPException) as duplicate:
        ingest_security_event(event)
    assert duplicate.value.status_code == 409

    evidence = collect_security_event_evidence(event_id, EvidenceSubmission(description="Analyst packet capture", source="analyst-console", details={"capture": "pcap-1"}))
    assert evidence["provenance"] == "user_supplied"

    filtered = list_security_events(category=EventCategory.NETWORK, severity=Severity.HIGH)
    assert [item["event_id"] for item in filtered] == [str(event_id)]

    rerun = investigate_security_event(event_id)
    assert evidence["evidence_id"] in rerun["evidence_references"]

    verification = verify_security_event(event_id)
    assert "checks" in verification
    assert get_security_event_verification(event_id) == verification


def test_security_event_api_rejects_invalid_events_and_exposes_correlations():
    _reset_central_engine()
    with pytest.raises(ValidationError):
        SecurityEvent(event_type="network_signal", category="network", source="x")

    with pytest.raises(ValidationError):
        SecurityEvent(event_type="bad-category", category="bad_category", source="x")

    ingest_security_event(SecurityEvent(event_type="network_signal", category="network", source="sensor-a", attributes={"entity_references": ["case-77"]}))
    ingest_security_event(SecurityEvent(event_type="agent_tool_denied", category="agent", source="finance-agent", attributes={"entity_references": ["case-77"]}))

    correlations = list_correlations()
    assert correlations[0]["shared_entities"] == ["case-77"]
    assert get_system_status()["storage"] == "in_memory_session_only"
    assert "/api/security-events/{event_id}/verify" in {route.path for route in app.routes}


def test_security_event_rejects_unsupported_category():
    _reset_central_engine()
    with pytest.raises(ValidationError):
        SecurityEvent(event_type="test", category="bad_category", source="s")

    with pytest.raises(ValidationError):
        SecurityEvent(event_type="test", category="network", source="s", bogus_field=True)


def test_security_event_provenance_and_evidence_boundary():
    _reset_central_engine()
    event = _make_event(EventCategory.SYSTEM)
    ingest_security_event(event)

    user_evidence = collect_security_event_evidence(
        event.event_id,
        EvidenceSubmission(
            description="user note",
            source="analyst-console",
            provenance=EvidenceProvenance.USER_SUPPLIED,
        ),
    )
    assert user_evidence["provenance"] == "user_supplied"

    fixture_evidence = collect_security_event_evidence(
        event.event_id,
        EvidenceSubmission(
            description="fixture note",
            provenance=EvidenceProvenance.SYNTHETIC_FIXTURE,
        ),
    )
    assert fixture_evidence["provenance"] == "synthetic_fixture"
    assert fixture_evidence["source"] == "test-source"

    real_evidence = collect_security_event_evidence(
        event.event_id,
        EvidenceSubmission(
            description="collected telemetry",
            provenance=EvidenceProvenance.ACTUAL_COLLECTED,
        ),
    )
    assert real_evidence["provenance"] == "actual_collected"

    all_evidence = list_evidence()
    assert {e["provenance"] for e in all_evidence} == {
        "user_supplied", "synthetic_fixture", "actual_collected",
    }


def test_central_engine_evidence_rejects_duplicate_id():
    _reset_central_engine()
    event = _make_event(EventCategory.SYSTEM)
    ingest_security_event(event)

    from core.evidence import EvidenceEngine, EvidenceRecord
    from uuid import UUID

    collided = UUID(int=1)
    engine = EvidenceEngine(evidence_id_factory=lambda: collided)
    engine.records[collided] = EvidenceRecord(
        evidence_id=collided,
        event_id=event.event_id,
        description="d",
        source="s",
    )

    with pytest.raises(ValueError) as exc_info:
        engine.collect(event, "dupe")
    assert "Duplicate evidence ID" in str(exc_info.value)


def test_security_event_unknown_event_handled_safely():
    _reset_central_engine()
    unknown_id = UUID(int=2)

    assert security_engine.get_event(unknown_id) is None
    assert security_engine.evidence_engine.get_event_evidence(unknown_id) == []
    assert security_engine.evidence_engine.get_evidence(unknown_id) is None

    investigation = security_engine.get_investigation(unknown_id)
    assert investigation is None

    with pytest.raises(ValueError, match="Event not found"):
        security_engine.investigate(unknown_id)

    with pytest.raises(ValueError, match="Event not found"):
        security_engine.collect_evidence(unknown_id, "desc")
