from core.engine import SecurityEventEngine
from core.schemas import (
    NormalizedInvestigationResult,
    ResponseState,
    SecurityEvent,
    Verdict,
)
from core.verification import VerificationEngine
from core import socrates_adapter
from uuid import uuid4


def test_investigation_preserves_event_evidence_references_and_fixture_boundary():
    engine = SecurityEventEngine()
    event = SecurityEvent(
        event_type="port_scan",
        category="network",
        source="203.0.113.99",
        target="campus-lab-service",
        severity="high",
    )
    engine.ingest(event)
    evidence = engine.collect_evidence(
        event.event_id,
        "Analyst supplied packet observation",
        {"packet_id": "pkt-1"},
        source="analyst-console",
    )

    result = engine.investigate(event.event_id)

    assert result.event_id == event.event_id
    assert evidence.evidence_id in result.evidence_references
    assert result.steps
    assert any("event-scoped evidence" in step.detail for step in result.steps)
    assert result.synthetic_evidence  # SOCrates local tool output is kept separate.
    assert any("synthetic" in limitation.lower() for limitation in result.evidence_limitations)
    assert engine.get_investigation(event.event_id) == result


def test_normalized_verification_requires_evidence_for_confirmed_breach():
    result = NormalizedInvestigationResult(
        event_id=SecurityEvent(event_type="test", category="system", source="test").event_id,
        status="closed",
        verdict=Verdict.CONFIRMED_BREACH,
        raw_verdict="confirmed_breach",
        confidence=0.9,
        reasoning="Evidence indicates compromise.",
        response_state=ResponseState.RESPONSE_RECOMMENDED,
    )

    verification = VerificationEngine().verify(result)

    assert verification.passed is False
    assert any(check["check"] == "evidence_references" for check in verification.failures)


def test_normalized_verification_accepts_recorded_simulated_response():
    from uuid import uuid4

    event = SecurityEvent(event_type="test", category="system", source="test")
    result = NormalizedInvestigationResult(
        event_id=event.event_id,
        status="closed",
        verdict=Verdict.ATTEMPTED_AND_CONTAINED,
        raw_verdict="attempted_and_contained",
        confidence=0.8,
        reasoning="The attempt was stopped by the simulator.",
        evidence_references=[uuid4()],
        response_state=ResponseState.RESPONSE_SIMULATED,
        response_reference="simulated_quarantine:case-1",
    )
    verification = VerificationEngine().verify(result)

    assert verification.passed is True
    assert verification.response_reference == "simulated_quarantine:case-1"


def test_unsupported_socrates_verdict_is_normalized_to_inconclusive(monkeypatch):
    class UnknownVerdictCase:
        def summary(self):
            return {
                "status": "closed",
                "verdict": "unrecognized_provider_verdict",
                "confidence": "high",
                "reasoning": "Provider-specific result.",
                "steps": [],
                "evidence": {},
                "actions_taken": [],
            }

    monkeypatch.setattr(socrates_adapter, "investigate", lambda alert: UnknownVerdictCase())
    event = SecurityEvent(event_type="test", category="system", source="test")

    result = socrates_adapter.investigate_event(event)

    assert result.raw_verdict == "unrecognized_provider_verdict"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_execution_reference_is_not_treated_as_execution_proof():
    event = SecurityEvent(event_type="test", category="system", source="test")
    result = NormalizedInvestigationResult(
        event_id=event.event_id,
        status="closed",
        verdict=Verdict.CONFIRMED_BREACH,
        raw_verdict="confirmed_breach",
        confidence=0.9,
        reasoning="Confirmed by evidence.",
        evidence_references=[uuid4()],
        response_state=ResponseState.RESPONSE_EXECUTED,
        response_reference="external-response-123",
    )

    verification = VerificationEngine().verify(result)

    assert verification.passed is False
    assert any(check["check"] == "executed_response_proof" for check in verification.failures)
