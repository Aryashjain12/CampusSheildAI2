from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class NetworkEvent(BaseModel):
    event_type: Literal["port_scan", "brute_force", "traffic_spike", "outbound_anomaly"]
    source_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    destination_id: str = Field(default="campus-lab-service", min_length=1, max_length=80)
    timestamp: datetime = Field(default_factory=utc_now)
    features: dict[str, float | int | str | bool] = Field(default_factory=dict)


class Incident(BaseModel):
    id: str
    event_type: str
    source_id: str
    severity: Literal["low", "medium", "high", "critical"]
    risk_score: int = Field(ge=0, le=100)
    title: str
    evidence: list[str]
    status: Literal["open", "response_pending", "contained", "resolved", "escalated"] = "open"
    created_at: datetime = Field(default_factory=utc_now)
    response_action: str | None = None
    verification: str | None = None
    investigation: dict | None = None
    verdict: str | None = None
    confidence: str | None = None
    reasoning: str | None = None
    action_history: list[dict] = Field(default_factory=list)


class ActionResult(BaseModel):
    incident_id: str
    action: str
    status: Literal["simulated", "rejected", "failed"]
    message: str
