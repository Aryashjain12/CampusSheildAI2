from core.verification import VerificationEngine
from core.investigation import Investigation
from core.schemas import Alert, Severity, Verdict


def create_investigation(verdict):
    alert = Alert(
        alert_id="TEST-001",
        source_ip="192.168.1.10",
        destination_host="server-01",
        signature="test_alert",
        severity=Severity.HIGH,
    )

    investigation = Investigation(alert)

    investigation.set_verdict(
        verdict=verdict,
        confidence=0.95,
        reasoning="Test investigation reasoning.",
    )

    return investigation


def test_confirmed_breach_requires_block():
    investigation = create_investigation(Verdict.CONFIRMED_BREACH)

    result = VerificationEngine().verify(investigation, is_blocked=True)

    assert result.passed is True


def test_confirmed_breach_without_block_fails():
    investigation = create_investigation(Verdict.CONFIRMED_BREACH)

    result = VerificationEngine().verify(investigation, is_blocked=False)

    assert result.passed is False


def test_false_positive_should_not_be_blocked():
    investigation = create_investigation(Verdict.FALSE_POSITIVE)

    result = VerificationEngine().verify(investigation, is_blocked=False)

    assert result.passed is True


def test_missing_reasoning_fails():
    investigation = create_investigation(Verdict.CONFIRMED_BREACH)
    investigation.reasoning = ""

    result = VerificationEngine().verify(investigation, is_blocked=True)

    assert result.passed is False

