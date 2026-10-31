import sys
from pathlib import Path

BACKEND_PATH = str(Path(__file__).resolve().parent.parent / "backend")

if BACKEND_PATH not in sys.path:
    sys.path.insert(0, BACKEND_PATH)

from agent.controller import investigate

from datetime import datetime, timezone
from typing import Iterable

from core.evidence import EvidenceRecord
from core.schemas import (
    NormalizedInvestigationResult,
    InvestigationStep,
    ResponseState,
    SecurityEvent,
    Verdict,
)


_SOC_RATES_VERDICTS = {verdict.value: verdict for verdict in Verdict}
_CONFIDENCE_MAP = {"low": 0.35, "medium": 0.6, "high": 0.85}


def _normalise_confidence(value: object) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    return _CONFIDENCE_MAP.get(str(value).lower(), 0.0)


def investigate_event(
    event: SecurityEvent,
    evidence_records: Iterable[EvidenceRecord] = (),
) -> NormalizedInvestigationResult:
    """Run SOCrates and expose its result through the central contract.

    Event-scoped evidence is passed as context and preserved as references.
    The current SOCrates fixture/tool output remains labelled as synthetic;
    it is not promoted to collected evidence.
    """
    records = list(evidence_records)
    alert = {
        "event_id": str(event.event_id),
        "event_type": event.event_type,
        "source_id": event.source,
        "destination_id": event.target,
        "source_ip": event.source,
        "dest_host": event.target,
        "severity": event.severity.value,
        "timestamp": event.timestamp.isoformat(),
        "signature": event.event_type,
        "central_evidence": [record.model_dump(mode="json") for record in records],
    }

    case = investigate(alert)
    summary = case.summary()
    raw_verdict = str(summary.get("verdict") or "inconclusive")
    verdict = _SOC_RATES_VERDICTS.get(raw_verdict, Verdict.INCONCLUSIVE)
    recommended_actions = (
        ["simulated_quarantine_recommended", "human_review"]
        if verdict == Verdict.CONFIRMED_BREACH
        else ["human_review"]
    )
    response_state = (
        ResponseState.RESPONSE_RECOMMENDED
        if verdict == Verdict.CONFIRMED_BREACH
        else ResponseState.INVESTIGATED
    )
    limitations = []
    if not records:
        limitations.append(
            "No event-scoped collected evidence was available; SOCrates results may rely on synthetic local fixtures."
        )
    limitations.append(
        "SOCrates fixture and tool output is synthetic unless an external evidence integration explicitly identifies it otherwise."
    )
    now = datetime.now(timezone.utc)
    socrates_evidence = dict(summary.get("evidence") or {})
    socrates_evidence.pop("central_event_evidence", None)
    return NormalizedInvestigationResult(
        event_id=event.event_id,
        status=str(summary.get("status") or "closed"),
        verdict=verdict,
        raw_verdict=raw_verdict,
        confidence=_normalise_confidence(summary.get("confidence")),
        reasoning=str(summary.get("reasoning") or "SOCrates returned no reasoning."),
        steps=[
            InvestigationStep(
                label=str(step.get("label", "SOCrates")),
                detail=str(step.get("detail", "")),
                timestamp=now,
            )
            for step in summary.get("steps", [])
        ],
        evidence_references=[record.evidence_id for record in records],
        synthetic_evidence=socrates_evidence,
        evidence_limitations=limitations,
        recommended_actions=recommended_actions,
        response_state=response_state,
        response_reference=(
            "socrates_simulated_response"
            if summary.get("actions_taken") else None
        ),
        previous_verdict=summary.get("previous_verdict"),
    )
