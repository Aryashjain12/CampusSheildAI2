from dataclasses import dataclass

from core.investigation import Investigation
from core.schemas import Verdict


@dataclass
class VerificationResult:
    passed: bool
    checks: list[dict]


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

    def verify(
        self,
        investigation: Investigation,
        is_blocked: bool,
    ) -> VerificationResult:

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

        return VerificationResult(
            passed=all(check["passed"] for check in checks),
            checks=checks,
        )
