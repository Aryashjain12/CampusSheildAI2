from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

from core.investigation import Investigation
from core.schemas import NormalizedInvestigationResult, ResponseState, Verdict


@dataclass
class VerificationResult:
    passed: bool
    checks: list[dict]
    failures: list[dict] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    investigation_reference: UUID | str | None = None
    response_reference: str | None = None


class VerificationEngine:

    SHOULD_BE_BLOCKED = {
        Verdict.CONFIRMED_BREACH,
    }

    SHOULD_NOT_BE_BLOCKED = {
        Verdict.FALSE_POSITIVE,
        Verdict.AUTHORIZED_ACTIVITY,
        Verdict.ATTEMPTED_AND_CONTAINED,
        Verdict.INCONCLUSIVE,
    }

    def verify(self, investigation: Investigation | NormalizedInvestigationResult, is_blocked: bool | None = None) -> VerificationResult:
        """Verify both legacy core cases and normalized SOCrates results."""
        if isinstance(investigation, NormalizedInvestigationResult):
            return self._verify_normalized(investigation)
        if is_blocked is None:
            raise ValueError("Legacy investigation verification requires is_blocked.")
        return self._verify_legacy(investigation, is_blocked)

    def _result(self, checks: list[dict], investigation_reference=None, response_reference=None) -> VerificationResult:
        failures = [check for check in checks if not check["passed"]]
        return VerificationResult(
            passed=not failures,
            checks=checks,
            failures=failures,
            investigation_reference=investigation_reference,
            response_reference=response_reference,
        )

    def _verify_legacy(self, investigation: Investigation, is_blocked: bool) -> VerificationResult:
        """Preserve the original verification contract for existing callers."""

        checks = []

        verdict = investigation.verdict

        if verdict in self.SHOULD_BE_BLOCKED:
            checks.append({
                "check": "response_state",
                "passed": is_blocked,
                "message": "Confirmed breach should be blocked.",
            })

        elif verdict in self.SHOULD_NOT_BE_BLOCKED:
            checks.append({
                "check": "response_state",
                "passed": not is_blocked,
                "message": "This verdict should not require an active block.",
            })

        action_attempted = any(
            action.get("action") in {"block", "simulated_quarantine"}
            for action in investigation.actions
        )

        checks.append({
            "check": "action_recorded",
            "passed": action_attempted == is_blocked or not action_attempted,
            "message": "Response action and reported state checked.",
        })

        reasoning_exists = bool(
            investigation.reasoning
            and investigation.reasoning.strip()
        )

        checks.append({
            "check": "reasoning",
            "passed": reasoning_exists,
            "message": "Investigation reasoning checked.",
        })

        return self._result(checks, investigation.alert.alert_id)

    def _verify_normalized(self, investigation: NormalizedInvestigationResult) -> VerificationResult:
        checks: list[dict] = []
        checks.append({
            "check": "verdict_contract",
            "passed": investigation.verdict in Verdict,
            "message": "Investigation verdict is part of the public CampusShield contract.",
        })
        checks.append({
            "check": "reasoning",
            "passed": bool(investigation.reasoning.strip()),
            "message": "Investigation contains a reasoning explanation.",
        })
        evidence_expected = investigation.verdict in {
            Verdict.CONFIRMED_BREACH,
            Verdict.ATTEMPTED_AND_CONTAINED,
        }
        checks.append({
            "check": "evidence_references",
            "passed": bool(investigation.evidence_references) if evidence_expected else True,
            "message": (
                "High-impact verdicts require event-scoped evidence references."
                if evidence_expected else "No event-scoped evidence reference is required for this verdict."
            ),
        })
        state = investigation.response_state
        response_recorded = bool(investigation.response_reference)
        requires_response_record = state in {
            ResponseState.RESPONSE_ATTEMPTED,
            ResponseState.RESPONSE_SIMULATED,
            ResponseState.RESPONSE_EXECUTED,
            ResponseState.RESPONSE_VERIFIED,
        }
        checks.append({
            "check": "response_reference",
            "passed": response_recorded if requires_response_record else True,
            "message": "Attempted, simulated, executed, and verified responses require a response reference.",
        })
        checks.append({
            "check": "executed_response_proof",
            "passed": state != ResponseState.RESPONSE_EXECUTED,
            "message": (
                "A response reference alone is not proof that containment executed; "
                "this MVP has no executed-response proof integration."
                if state == ResponseState.RESPONSE_EXECUTED else
                "No executed-response proof is required for this response state."
            ),
        })
        checks.append({
            "check": "response_state_consistency",
            "passed": not (
                investigation.verdict == Verdict.ATTEMPTED_AND_CONTAINED
                and state in {ResponseState.DETECTED, ResponseState.INVESTIGATED, ResponseState.RESPONSE_RECOMMENDED}
            ),
            "message": "A contained verdict requires a recorded attempted, simulated, executed, or verified response.",
        })
        return self._result(
            checks,
            investigation.investigation_id,
            investigation.response_reference,
        )
