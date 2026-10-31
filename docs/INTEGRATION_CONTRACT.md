# CampusShield AI 2.0 integration contract

This is the source-backed integration agreement for Members A, B, and C. The canonical cross-module envelope is `core.schemas.SecurityEvent`. It is distinct from the existing `agent_network.models.CommonEvent`, which is used internally by the scripted agent network. New integrations must emit `SecurityEvent` objects to the central engine; they must not introduce another cross-module event schema.

## 1. Unified `SecurityEvent` contract

`SecurityEvent` is a Pydantic model with `extra="forbid"`: payload keys outside the fields below are rejected. Timestamps must be timezone-aware. Python serialization for API responses uses `model_dump(mode="json")`.

| Field | Type | Default | Rules |
|---|---|---|---|
| `event_id` | `UUID` | `uuid4()` | Unique event identifier. `SecurityEventEngine.ingest()` rejects an ID already in its in-memory event store. |
| `schema_version` | literal string `"1.0"` | `"1.0"` | No other value is accepted. |
| `event_type` | `str` | required | Length 1–100. |
| `category` | `EventCategory` | required | One of the values below. |
| `source` | `str` | required | Length 3–255. |
| `target` | `str \| None` | `None` | When supplied, maximum length 255. |
| `severity` | `Severity` | `Severity.LOW` (`"low"`) | One of the values below. |
| `timestamp` | timezone-aware `datetime` | current UTC time | Naive values are rejected with `Timestamp must include timezone information`. |
| `attributes` | `dict[str, Any]` | `{}` | Module-specific detail. |
| `metadata` | `dict[str, Any]` | `{}` | Module-specific supporting context. `entity_references`, if a list of non-empty strings, participates in central correlation. |

Supported `EventCategory` values are `network`, `agent`, `memory`, `dependency`, `threat_intelligence`, `cryptography`, and `system`. Supported `Severity` values are `low`, `medium`, `high`, and `critical`.

### Valid examples by category

```python
from core.schemas import EventCategory, SecurityEvent

network_event = SecurityEvent(event_type="brute_force", category=EventCategory.NETWORK,
    source="networkshield", target="campus-lab-login", severity="high",
    attributes={"failed_logins": 14}, metadata={"entity_references": ["ip:198.51.100.44"]})
agent_event = SecurityEvent(event_type="instruction_in_data_detected", category=EventCategory.AGENT,
    source="agentshield", severity="high", attributes={"agent": "helpdesk"})
memory_event = SecurityEvent(event_type="poisoned_memory_detected", category=EventCategory.MEMORY,
    source="memoryshield", severity="high", attributes={"memory_entry": "mem_123"})
dependency_event = SecurityEvent(event_type="vulnerable_dependency_detected", category=EventCategory.DEPENDENCY,
    source="depguardx", severity="medium", attributes={"package": "example", "version": "1.0"})
threat_intel_event = SecurityEvent(event_type="indicator_match", category=EventCategory.THREAT_INTELLIGENCE,
    source="pulseguardx", severity="medium", attributes={"indicator": "example-indicator"})
crypto_event = SecurityEvent(event_type="weak_crypto_configuration", category=EventCategory.CRYPTOGRAPHY,
    source="cryptoshield", severity="high", attributes={"algorithm": "example"})
system_event = SecurityEvent(event_type="module_health_changed", category=EventCategory.SYSTEM,
    source="module-monitor", severity="low", attributes={"module": "NetworkShield", "status": "degraded"})
```

The examples illustrate only the schema; they do not imply that every named module currently emits central events. The current system-status endpoint explicitly reports AgentShield as not yet wired into the central event API and several modules as not integrated.

## 2. Evidence contract

`EvidenceRecord` is the central evidence model:

| Field | Type | Default |
|---|---|---|
| `evidence_id` | `UUID` | `uuid4()` |
| `event_id` | `UUID` | required |
| `description` | `str` | required |
| `source` | `str` | required |
| `provenance` | `EvidenceProvenance` | `actual_collected` |
| `collected_at` | timezone-aware `datetime` | current UTC time |
| `details` | `dict[str, Any]` | `{}` |

`EvidenceProvenance` values are:

- `actual_collected` — evidence actually collected by an integration.
- `user_supplied` — evidence supplied through a user/API submission.
- `synthetic_fixture` — fixture or simulation evidence.
- `inferred` — derived rather than directly observed evidence.

Synthetic fixture evidence must never be represented as `actual_collected` telemetry. The SOCrates adapter deliberately retains SOCrates fixture/tool output in `NormalizedInvestigationResult.synthetic_evidence` and states that it is synthetic unless an external evidence integration identifies it otherwise.

`EvidenceEngine` stores evidence in memory, keyed by `evidence_id`:

```python
collect(event: SecurityEvent, description: str, details: dict[str, Any] | None = None,
        *, source: str | None = None,
        provenance: EvidenceProvenance = EvidenceProvenance.ACTUAL_COLLECTED) -> EvidenceRecord
get_evidence(evidence_id: UUID) -> EvidenceRecord | None
get_event_evidence(event_id: UUID) -> list[EvidenceRecord]
list_evidence() -> list[EvidenceRecord]
```

`collect()` uses `event.source` when `source` is omitted, uses `{}` for omitted details, and raises `ValueError` if its generated evidence ID collides with an existing record. `get_evidence()` returns `None` for an unknown ID; the two list methods return empty lists when no records match.

The HTTP evidence submission model is `EvidenceSubmission` (`extra="forbid"`): `description` is required (1–2,000 characters); `details` defaults to `{}`; `source` is optional but, if supplied, is 1–255 characters; `provenance` defaults to `user_supplied`.

## 3. Central engine contract

`SecurityEventEngine` is in-memory and has these public methods:

```python
ingest(event: SecurityEvent) -> SecurityEvent
investigate(event_id: UUID) -> NormalizedInvestigationResult
collect_evidence(event_id: UUID, description: str, details: dict | None = None,
                 *, source: str | None = None, provenance=None) -> EvidenceRecord
get_event(event_id: UUID) -> SecurityEvent | None
list_events(*, category: EventCategory | None = None, severity: Severity | None = None,
            source: str | None = None, event_type: str | None = None,
            since: datetime | None = None, until: datetime | None = None) -> list[SecurityEvent]
get_investigation(event_id: UUID) -> NormalizedInvestigationResult | None
list_correlations() -> list[EventCorrelation]
```

`ingest()` raises `ValueError("Duplicate event ID: ...")` for a duplicate event. `investigate()` and `collect_evidence()` raise `ValueError("Event not found")` for an unknown event. `list_events()` applies exact category, severity, source, and event-type filters; applies inclusive `since`/`until` timestamp bounds; and returns newest-first. The engine creates deterministic central correlations only across different categories that share source/target or `entity_references` and are no more than 900 seconds apart. An `EventCorrelation` contains a generated ID, exactly two event IDs, at least one shared entity, a non-negative delta in seconds, a reason, and a UTC creation time.

The implemented FastAPI boundary exposes these engine capabilities:

- `POST /api/security-events` returns HTTP 201 with `accepted`, serialized `event`, and serialized `investigation`; duplicate-event `ValueError`s become HTTP 409.
- `GET /api/security-events` supports the engine filters and returns HTTP 422 when `since > until`.
- `GET /api/security-events/{event_id}` returns HTTP 404 when absent.
- `POST /api/security-events/{event_id}/evidence` returns HTTP 201, or HTTP 404 for an unknown event.
- `GET /api/security-events/{event_id}/evidence`, `POST /api/security-events/{event_id}/investigate`, `GET /api/security-events/{event_id}/investigation`, `POST /api/security-events/{event_id}/verify`, `GET /api/security-events/{event_id}/verification`, `GET /api/evidence`, and `GET /api/correlations` are implemented.

`/api/system/status` explicitly reports session-only in-memory storage: events, evidence, investigations, verifications, and correlations are lost on restart.

## 4. Investigation, recommendation, and verification lifecycle

`NormalizedInvestigationResult` is the stable SOCrates-to-central-engine result. Its fields are: generated `investigation_id: UUID`; required `event_id: UUID`, `status: str`, `verdict: Verdict`, `raw_verdict: str`, and `reasoning: str`; `confidence: float` constrained to 0.0–1.0; `steps: list[InvestigationStep]` (default empty); `evidence_references: list[UUID]` (default empty); `synthetic_evidence: dict[str, Any]` (default `{}`); `evidence_limitations: list[str]` (default empty); `recommended_actions: list[str]` (default empty); `response_state` (default `investigated`); optional `response_reference` and `previous_verdict`; and UTC `investigated_at`.

`Verdict` values are `confirmed_breach`, `false_positive`, `authorized_activity`, `attempted_and_contained`, and `inconclusive`. `raw_verdict` preserves the SOCrates value; any unsupported SOCrates value is normalized to `inconclusive`.

`ResponseState` values are `detected`, `investigated`, `response_recommended`, `response_attempted`, `response_simulated`, `response_executed`, and `response_verified`. The SOCrates adapter currently recommends `simulated_quarantine_recommended` and `human_review` for a confirmed breach, marks it `response_recommended`, and otherwise recommends `human_review` with state `investigated`. This is a recommendation boundary: an LLM recommendation is not authorization to execute containment. The application description states that it is a safe MVP with simulated response and no real traffic blocking.

`VerificationEngine.verify()` accepts either a legacy `Investigation` plus `is_blocked`, or a `NormalizedInvestigationResult`. A legacy call without `is_blocked` raises `ValueError`. For normalized results, verification checks: public verdict membership; non-blank reasoning; evidence references for `confirmed_breach` and `attempted_and_contained`; a response reference for attempted/simulated/executed/verified response states; and that an `attempted_and_contained` verdict is not left merely detected, investigated, or recommended. It returns `VerificationResult(passed, checks, failures, timestamp, investigation_reference, response_reference)`; it does not itself execute a response.

## 5. Agent-network compatibility boundary

The current scripted agent network emits `CommonEvent`, not `SecurityEvent`. Its fields are `id`, `source`, `time` (UTC ISO string), `entity`, `event_type`, `evidence`, `severity` (`info`, `low`, `medium`, `high`, or `critical`), `confidence` (0–1), and `related_entities`. Its Helpdesk, Library, Finance, and Student Support agents produce events for conditions such as instruction-in-data detection, compromise, canary/decoy use, and permission failures.

`NetworkCorrelator` also produces `CommonEvent` values (`network_alert_recorded` and `network_correlation_detected`) and retains its own correlation list. `ProvenanceTracer` traces affected agent states backwards across message-bus and shared-memory relay edges to identify a patient-zero candidate. These mechanisms are not currently adapters to `SecurityEventEngine`; an integration must map their output to the canonical central `SecurityEvent` plus provenance-labelled `EvidenceRecord` without silently discarding source events.

## 6. Teammate integration responsibilities

### Member A

- Own central event and evidence architecture, SOCrates and verification integration, central correlations, and the central APIs.
- Own NVIDIA Nemotron advisory integration when present, while retaining the deterministic investigation path when NVIDIA is unavailable.
- Preserve the synthetic/actual evidence distinction and the in-memory-storage limitation until persistence is supplied.

### Member B

- Own NetworkShield, AgentShield, MemoryShield, DepGuardX, PulseGuardX, and CryptoShield detection modules.
- Make every module emit compatible `SecurityEvent` objects, attach event-scoped evidence with correct provenance, and expose module health/configuration.
- Do not claim that a fixture, scenario, or simulation is live telemetry. The current module-status endpoint reports only NetworkShield as available with synthetic network detection; AgentShield is not yet wired to the central event API, and the remaining named modules are not integrated.

### Member C

- Own response approval workflow, persistent storage, dashboard/incident views, audit logs, and deployment.
- Ensure any response presented as simulated remains labelled simulated, and require an approval workflow before any future executed containment action.

## 7. Required module integration checklist

Every module integration must provide:

1. Module name and version.
2. Purpose and supported `EventCategory` detection categories.
3. Initialization/configuration method.
4. Health/status method.
5. `SecurityEvent`-compatible output.
6. `EvidenceEngine`-compatible, provenance-labelled evidence output.
7. Defined error handling; unknown/failed events must not be silently discarded.
8. Unit tests.
9. Dependencies.
10. Known limitations, including fixture/simulation status and whether persistence or live telemetry exists.

## 8. Integration principles

- Preserve existing APIs and working features; do not change `PROJECT_CHARTER.md` as part of integration work.
- Use `SecurityEvent` as the only cross-module event envelope; adapt legacy local schemas rather than duplicating canonical schemas.
- Avoid direct coupling between detection modules. Use the central engine/event-and-evidence boundary.
- Do not silently discard events.
- Do not describe fixtures as live telemetry, or synthetic evidence as actual collected evidence.
- Do not describe simulated actions as real containment.
- Keep the deterministic SOCrates path available when NVIDIA is unavailable.
