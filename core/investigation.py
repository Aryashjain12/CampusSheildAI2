
from datetime import datetime, timezone

from core.schemas import Alert, Evidence, Verdict, InvestigationResult


class Investigation:
    """
    Maintains the complete state of one security investigation.
    """

    def __init__(self, alert: Alert):
        self.alert = alert

        # Evidence collected during investigation
        self.evidence: list[Evidence] = []

        # Chronological investigation history
        self.steps: list[dict] = []

        # Actions attempted by the response engine
        self.actions: list[dict] = []

        # Current investigation decision
        self.verdict: Verdict | None = None
        self.confidence: float | None = None
        self.reasoning: str | None = None

        # Preserve every decision for auditing
        self.decision_history: list[dict] = []

        self.status = "open"

        self.created_at = datetime.now(timezone.utc)

    def add_step(self, label: str, detail: str):
        """Record one investigation event."""

        self.steps.append({
            "label": label,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def add_evidence(self, evidence: Evidence):
        """Attach evidence to this investigation."""

        self.evidence.append(evidence)

        self.add_step(
            "Evidence collected",
            f"{evidence.source}: {evidence.description}"
        )

    def record_action(self, action: str, status: str):
        """Record an attempted response action and its result."""

        self.actions.append({
            "action": action,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        self.add_step(
            "Response action",
            f"{action} - {status}"
        )

    def set_verdict(
        self,
        verdict: Verdict,
        confidence: float,
        reasoning: str
    ):
        """Save an investigation decision."""

        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Confidence must be between 0 and 1")

        self.verdict = verdict
        self.confidence = confidence
        self.reasoning = reasoning
        self.status = "closed"

        self.decision_history.append({
            "verdict": verdict.value,
            "confidence": confidence,
            "reasoning": reasoning,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        self.add_step(
            "Investigation verdict",
            f"{verdict.value} (confidence: {confidence})"
        )

    def revise_verdict(
        self,
        verdict: Verdict,
        confidence: float,
        reasoning: str
    ):
        """Reconsider a closed investigation using new evidence."""

        if self.status != "closed":
            raise ValueError("Only closed investigations can be revised")

        self.add_step(
            "Decision reconsideration",
            "New information requires a review"
        )

        self.set_verdict(verdict, confidence, reasoning)
        self.status = "closed_after_review"

    def create_result(self) -> InvestigationResult:
        """Generate a structured investigation result."""

        if self.verdict is None:
            raise ValueError("Investigation has no verdict yet")

        return InvestigationResult(
            alert_id=self.alert.alert_id,
            verdict=self.verdict,
            confidence=self.confidence,
            reasoning=self.reasoning,
            evidence=self.evidence.copy()
        )
