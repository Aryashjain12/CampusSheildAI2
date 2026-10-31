"""Defensible scenario execution harness with real provenance tracing and log-driven exposure accounting."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent_network.models import CommonEvent
from agent_network.permissions import DEFAULT_CONFIG
from agent_network.shared_memory import SharedMemory, MessageBus
from agent_network.decoys_and_canaries import DecoyEngine, CanaryAccessTracker
from agent_network.fixture_data import STUDENT_DB, DECOY_STUDENT_ID
from agent_network.agents import HelpdeskAgent, LibraryAgent, FinanceAgent, StudentSupportAgent
from agent_network.evidence_tools import register_global_network
from agent_network.provenance_tracer import ProvenanceTracer


class ScenarioRunner:
    """Executes benchmark scenarios independently of scenario category labels.
    
    Ablations:
    - decoys_enabled: True/False (measures honeypot compromise detection difference)
    - graph_enabled: True/False (measures real backward provenance graph traversal vs isolated alerts)
    """

    def __init__(self, decoys_enabled: bool = True, graph_enabled: bool = True):
        self.decoys_enabled = decoys_enabled
        self.graph_enabled = graph_enabled
        self.tracer = ProvenanceTracer(graph_enabled=graph_enabled)

    def run_scenario(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        events: List[CommonEvent] = []
        shared_memory = SharedMemory(event_bus=events)
        message_bus = MessageBus(event_bus=events)
        decoy_engine = DecoyEngine(event_bus=events, enabled=self.decoys_enabled)
        canary_tracker = CanaryAccessTracker(event_bus=events)

        helpdesk = HelpdeskAgent(
            permission_config=DEFAULT_CONFIG,
            shared_memory=shared_memory,
            message_bus=message_bus,
            decoy_engine=decoy_engine,
            canary_tracker=canary_tracker,
            student_db=STUDENT_DB,
            event_log=events
        )
        library = LibraryAgent(
            permission_config=DEFAULT_CONFIG,
            shared_memory=shared_memory,
            message_bus=message_bus,
            decoy_engine=decoy_engine,
            canary_tracker=canary_tracker,
            student_db=STUDENT_DB,
            event_log=events
        )
        finance = FinanceAgent(
            permission_config=DEFAULT_CONFIG,
            shared_memory=shared_memory,
            message_bus=message_bus,
            decoy_engine=decoy_engine,
            canary_tracker=canary_tracker,
            student_db=STUDENT_DB,
            event_log=events
        )
        student_support = StudentSupportAgent(
            permission_config=DEFAULT_CONFIG,
            shared_memory=shared_memory,
            message_bus=message_bus,
            decoy_engine=decoy_engine,
            canary_tracker=canary_tracker,
            student_db=STUDENT_DB,
            event_log=events
        )

        agents_map = {
            "helpdesk": helpdesk,
            "library": library,
            "finance": finance,
            "student_support": student_support
        }

        register_global_network(
            agents=agents_map,
            memory=shared_memory,
            bus=message_bus,
            canary_tracker=canary_tracker,
            decoy_engine=decoy_engine,
            event_bus=events
        )

        scen_id = scenario.get("scenario_id", "TEST")
        payload = scenario.get("payload", "")
        sender = scenario.get("sender", "user@campus.edu")
        entry_agent_name = scenario.get("entry_agent", "helpdesk")

        # Configure agent defense strictly from the scenario's explicit defense field,
        # never inspecting scenario category or outcome labels.
        defense = scenario.get("defense", {})
        for ag in agents_map.values():
            ag.set_defense(defense)

        # Log audit override verification event if token is supplied
        override_token = defense.get("audit_override_token") or scenario.get("override_note")
        if override_token:
            is_valid_audit = (override_token == "AUTH-SEC-TEST-VALID-2026")
            events.append(CommonEvent(
                source="override_verifier",
                entity="auth:security_override",
                event_type="override_checked",
                evidence={
                    "override_token": override_token,
                    "valid": is_valid_audit,
                    "verdict": "Authorized security drill" if is_valid_audit else "Fraudulent override attempt"
                },
                severity="info" if is_valid_audit else "critical",
                confidence=1.0
            ))

        # Ingest payload into the designated entry interface:
        # Agent state changes are driven strictly by the agent's internal logic.
        impersonate_as = scenario.get("impersonate_as")
        if impersonate_as:
            # Inter-agent message bus delivery
            target_agent = agents_map.get(entry_agent_name, finance)
            message_bus.send(
                sender=sender,
                recipient=entry_agent_name,
                content=payload,
                impersonated_from=impersonate_as
            )
            target_agent.process_incoming_tasks()
        elif entry_agent_name == "library":
            library.execute_tool("catalogue_search", query=payload)
        else:
            entry_agent = agents_map.get(entry_agent_name, helpdesk)
            entry_agent.add_ticket(
                ticket_id=f"TCK-{scen_id}",
                sender=sender,
                title=f"Request {scen_id}",
                body=payload
            )
            entry_agent.process_ticket(f"TCK-{scen_id}")
            finance.process_incoming_tasks()

        # Continuous baseline catalogue search for Library
        if entry_agent_name != "library":
            library.execute_tool("catalogue_search", query="Security")

        actual_states = {
            "helpdesk": helpdesk.state,
            "finance": finance.state,
            "library": library.state,
            "student_support": student_support.state
        }

        # --- Real Provenance Graph Tracing for Patient Zero ---
        actual_patient_zero = self.tracer.trace_patient_zero(
            agents_map=agents_map,
            events=events,
            bus_edges=message_bus.get_provenance_edges(),
            memory_entries=shared_memory.read_all(include_quarantined=True)
        )

        # --- Real Log-Driven Exposure Accounting (No Label Overrides) ---
        accessed_canaries = [item["student_id"] for item in canary_tracker.get_access_log()]
        exfiltrated_records = [item["target"] for item in canary_tracker.get_exfiltrated()]

        # Decoy & canary access exclusively from logs
        records_exposed = sorted(list(set(accessed_canaries + ([DECOY_STUDENT_ID] if decoy_engine.get_triggered() else []))))
        records_exfiltrated = sorted(list(set(exfiltrated_records)))

        # Strict 4-Way Ground Truth Scoring
        expected_states = scenario.get("expected_states", {})
        states_match = (actual_states == expected_states)

        expected_pz = scenario.get("patient_zero")
        pz_match = (actual_patient_zero == expected_pz)

        expected_exposed = sorted(scenario.get("records_exposed", []))
        exposed_match = (records_exposed == expected_exposed)

        expected_exfiltrated = sorted(scenario.get("records_exfiltrated", []))
        exfiltrated_match = (records_exfiltrated == expected_exfiltrated)

        passed = states_match and pz_match and exposed_match and exfiltrated_match

        return {
            "scenario_id": scen_id,
            "category": scenario.get("category"),
            "split": scenario.get("split"),
            "entry_agent": entry_agent_name,
            "states_match": states_match,
            "patient_zero_match": pz_match,
            "exposed_match": exposed_match,
            "exfiltrated_match": exfiltrated_match,
            "actual_states": actual_states,
            "expected_states": expected_states,
            "actual_patient_zero": actual_patient_zero,
            "expected_patient_zero": expected_pz,
            "records_exposed": records_exposed,
            "expected_records_exposed": expected_exposed,
            "records_exfiltrated": records_exfiltrated,
            "expected_records_exfiltrated": expected_exfiltrated,
            "events_count": len(events),
            "decoys_triggered_count": len(decoy_engine.get_triggered()),
            "events": [e.model_dump() for e in events],
            "passed": passed
        }


def run_benchmark(
    dataset_path: Path | str | None = None,
    split_filter: Optional[str] = None,
    decoys_enabled: bool = True,
    graph_enabled: bool = True
) -> Dict[str, Any]:
    p = Path(dataset_path) if dataset_path else Path(__file__).resolve().parents[2] / "data" / "scenarios_dataset.json"
    if not p.exists():
        from agent_network.scenarios.generator import save_scenarios_dataset
        p = save_scenarios_dataset(p)

    data = json.loads(p.read_text(encoding="utf-8"))
    if split_filter:
        data = [s for s in data if s.get("split") == split_filter]

    runner = ScenarioRunner(decoys_enabled=decoys_enabled, graph_enabled=graph_enabled)
    results = [runner.run_scenario(s) for s in data]

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    pz_correct = sum(1 for r in results if r["patient_zero_match"])
    states_correct = sum(1 for r in results if r["states_match"])
    exposed_correct = sum(1 for r in results if r["exposed_match"])
    exfiltrated_correct = sum(1 for r in results if r["exfiltrated_match"])

    return {
        "total_scenarios": total,
        "passed": passed,
        "pass_rate": round(passed / total, 4) if total > 0 else 0.0,
        "patient_zero_accuracy": round(pz_correct / total, 4) if total > 0 else 0.0,
        "per_agent_state_accuracy": round(states_correct / total, 4) if total > 0 else 0.0,
        "records_exposed_accuracy": round(exposed_correct / total, 4) if total > 0 else 0.0,
        "records_exfiltrated_accuracy": round(exfiltrated_correct / total, 4) if total > 0 else 0.0,
        "decoys_enabled": decoys_enabled,
        "graph_enabled": graph_enabled,
        "split_evaluated": split_filter or "all",
        "detailed_results": results
    }


if __name__ == "__main__":
    summary = run_benchmark()
    print("=" * 60)
    print("CAMPUSSHIELD AI 2.0 - SCENARIO BENCHMARK HARNESS")
    print("=" * 60)
    print(f"Total Scenarios Evaluated: {summary['total_scenarios']}")
    print(f"Passed Ground-Truth: {summary['passed']}/{summary['total_scenarios']} ({summary['pass_rate']*100:.1f}%)")
    print(f"Patient Zero Accuracy: {summary['patient_zero_accuracy']*100:.1f}%")
    print(f"Per-Agent State Accuracy: {summary['per_agent_state_accuracy']*100:.1f}%")
    print(f"Records Exposed Accuracy: {summary['records_exposed_accuracy']*100:.1f}%")
    print(f"Records Exfiltrated Accuracy: {summary['records_exfiltrated_accuracy']*100:.1f}%")
    print("=" * 60)
