from datetime import datetime, timezone

class Investigation:
    """Auditable per-alert case state used by SOCrates investigation workflow."""
    def __init__(self, alert):
        self.alert = alert
        self.evidence = {}
        self.actions_taken = []
        self.steps = []
        self.verdict = None
        self.confidence = None
        self.reasoning = None
        self.status = "open"
        self.created_at = datetime.now(timezone.utc).isoformat()

    def add_step(self, label, detail):
        self.steps.append({"label": str(label), "detail": str(detail)})

    def add_evidence(self, key, value):
        self.evidence[key] = value

    def record_action(self, action):
        self.actions_taken.append(action)

    def set_verdict(self, verdict, confidence, reasoning):
        self.verdict, self.confidence, self.reasoning = verdict, confidence, reasoning
        self.status = "closed"

    def apply_new_evidence(self, note, new_verdict, new_confidence, new_reasoning):
        self.evidence["new_information"] = note
        self.previous_verdict = self.verdict
        self.previous_reasoning = self.reasoning
        self.verdict, self.confidence, self.reasoning = new_verdict, new_confidence, new_reasoning
        self.status = "closed_after_review"

    def summary(self):
        return {"alert": self.alert, "status": self.status, "verdict": self.verdict,
                "confidence": self.confidence, "reasoning": self.reasoning,
                "evidence": self.evidence, "actions_taken": self.actions_taken,
                "steps": self.steps, "created_at": self.created_at,
                "previous_verdict": getattr(self, "previous_verdict", None)}
