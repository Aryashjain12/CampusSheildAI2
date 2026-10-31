from typing import Literal
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


# 1. Security alert severity
class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# 2. Investigation verdicts
class Verdict(str, Enum):
    CONFIRMED_BREACH = "confirmed_breach"
    FALSE_POSITIVE = "false_positive"
    AUTHORIZED_ACTIVITY = "authorized_activity"
    ATTEMPTED_AND_CONTAINED = "attempted_and_contained"
    INCONCLUSIVE = "inconclusive"


# 3. Normalized security alert
@dataclass
class Alert:
    alert_id: str
    source_ip: str
    destination_host: str
    signature: str
    severity: Severity
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: dict = field(default_factory=dict)


# 4. Evidence collected during investigation
@dataclass
class Evidence:
    evidence_id: str
    source: str
    description: str
    supports_compromise: bool | None = None
    observed_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: dict = field(default_factory=dict)


# 5. Final investigation result
@dataclass
class InvestigationResult:
    alert_id: str
    verdict: Verdict
    confidence: float
    reasoning: str
    evidence: list[Evidence] = field(default_factory=list)
    recommended_action: str = "human_review"
    investigated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ============================================================
# Unified Security Event Schema — CampusShield AI 2.0
# ============================================================

from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventCategory(str, Enum):
    """Broad security domains that generate events."""

    NETWORK = "network"
    AGENT = "agent"
    MEMORY = "memory"
    DEPENDENCY = "dependency"
    THREAT_INTELLIGENCE = "threat_intelligence"
    CRYPTOGRAPHY = "cryptography"
    SYSTEM = "system"


class SecurityEvent(BaseModel):
    """
    Common event format used by all CampusShield modules.

    Different modules can provide different attributes while
    following the same outer event structure.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: UUID = Field(default_factory=uuid4)

    schema_version: Literal["1.0"] = "1.0"

    event_type: str = Field(min_length=1, max_length=100)

    category: EventCategory

    source: str = Field(min_length=1, max_length=255)

    target: str | None = Field(default=None, max_length=255)

    severity: Severity = Severity.LOW

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    attributes: dict[str, Any] = Field(default_factory=dict)

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        """Reject timestamps that do not specify a timezone."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must include timezone information")

        return value
