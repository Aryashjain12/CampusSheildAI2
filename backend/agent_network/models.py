"""Data models for CampusShield AI 2.0 multi-agent network, security events, and ground truth."""
from datetime import datetime, timezone
import uuid
from typing import Any, Literal
from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CommonEvent(BaseModel):
    """Common Event Format agreed with Member A and Member C.
    
    Fields: id, source, time, entity, event_type, evidence, severity, confidence, related_entities.
    """
    id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    source: str
    time: str = Field(default_factory=utc_now_iso)
    entity: str
    event_type: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    related_entities: list[str] = Field(default_factory=list)


class StudentRecord(BaseModel):
    """Student database record representing sensitive campus data."""
    student_id: str
    name: str
    email: str
    department: str
    semester: int
    fee_total: float
    fee_balance: float
    fee_status: Literal["paid", "pending", "overdue"]
    gpa: float
    academic_standing: Literal["good", "probation", "honors"]
    is_canary: bool = False
    canary_marker: str | None = None
    is_decoy: bool = False


class MemoryEntry(BaseModel):
    """Shared memory entry between agents."""
    id: str = Field(default_factory=lambda: f"mem_{uuid.uuid4().hex[:8]}")
    agent: str
    timestamp: str = Field(default_factory=utc_now_iso)
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    quarantined: bool = False


class BusMessage(BaseModel):
    """Message sent over inter-agent message bus."""
    id: str = Field(default_factory=lambda: f"msg_{uuid.uuid4().hex[:8]}")
    sender: str
    recipient: str
    content: str
    timestamp: str = Field(default_factory=utc_now_iso)
    impersonated_from: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolCallResult(BaseModel):
    """Outcome of an agent attempting to invoke a tool."""
    agent: str
    tool_name: str
    allowed: bool
    success: bool
    data: Any = None
    error: str | None = None
    event: CommonEvent | None = None


AgentStateName = Literal["clean", "exposed", "attacked_but_resisted", "compromised"]


class ScenarioDefense(BaseModel):
    """Explicit defense configuration for reproducible evaluation."""
    injection_guardrail: bool = False
    audit_override_token: str | None = None


class ScenarioGroundTruth(BaseModel):
    """Ground truth specification for a benchmark evaluation scenario."""
    scenario_id: str
    name: str
    description: str
    category: str
    split: Literal["tuning", "locked"]
    entry_agent: str | None = None
    patient_zero: str | None = None
    expected_states: dict[str, AgentStateName] = Field(default_factory=dict)
    records_exposed: list[str] = Field(default_factory=list)
    records_exfiltrated: list[str] = Field(default_factory=list)
    defense: ScenarioDefense = Field(default_factory=ScenarioDefense)
    metadata: dict[str, Any] = Field(default_factory=dict)
