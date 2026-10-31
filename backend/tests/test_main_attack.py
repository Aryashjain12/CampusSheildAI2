"""Phase 2 tests: End-to-end main attack story, decoys, canaries, and evidence tools."""
from pathlib import Path
import json
from agent_network.attacks.run_main_story import run_main_attack_story
from agent_network.evidence_tools import (
    read_agent_log,
    read_memory,
    list_permissions,
    list_canary_access,
    get_provenance_graph
)


def test_main_attack_story_runs_end_to_end(tmp_path):
    sample_file = tmp_path / "test_sample_events.json"
    result = run_main_attack_story(output_file=sample_file)

    # 1. Spread strip verification
    assert result["patient_zero"] == "helpdesk"
    assert result["agent_states"]["helpdesk"] == "compromised"
    assert result["agent_states"]["finance"] == "exposed"
    assert result["agent_states"]["library"] == "clean"
    assert "helpdesk: compromised" in result["spread_strip"]
    assert "finance: exposed" in result["spread_strip"]
    assert "library: clean" in result["spread_strip"]

    # 2. Canary and Decoy verification
    assert "STU-2026-007" in result["records_exposed"]
    assert "STU-2026-007" in result["records_exfiltrated"]
    assert len(result["decoys_triggered"]) > 0

    # 3. Sample Event file written and valid
    assert sample_file.exists()
    assert result["sample_event_file"] == str(sample_file)
    events_data = json.loads(sample_file.read_text(encoding="utf-8"))
    assert len(events_data) == result["events_count"]
    assert result["events"] == events_data
    first_evt = events_data[0]
    for required_key in ["id", "source", "time", "entity", "event_type", "evidence", "severity", "confidence", "related_entities"]:
        assert required_key in first_evt


def test_main_attack_story_without_output_does_not_modify_shared_fixture():
    fixture_path = Path(__file__).resolve().parents[1] / "data" / "sample_events.json"
    fixture_before = fixture_path.read_bytes()

    result = run_main_attack_story()

    assert result["sample_event_file"] is None
    assert len(result["events"]) == result["events_count"]
    assert fixture_path.read_bytes() == fixture_before


def test_agent_evidence_tools_for_controller():
    # Verify Member A's investigation controller tools
    permissions = list_permissions()
    assert "helpdesk" in permissions
    assert "finance" in permissions
    assert "library" in permissions
    assert "student_support" in permissions

    # Logs
    logs = read_agent_log()
    assert isinstance(logs, list)

    # Memory
    mem = read_memory()
    assert isinstance(mem, list)

    # Canary access
    canary_logs = list_canary_access()
    assert isinstance(canary_logs, list)
    assert any(c["student_id"] == "STU-2026-007" for c in canary_logs)

    # Provenance Graph
    graph = get_provenance_graph()
    assert "nodes" in graph
    assert "edges" in graph
    node_ids = [n["id"] for n in graph["nodes"]]
    assert "agent:helpdesk" in node_ids
    assert "agent:finance" in node_ids
    assert "agent:library" in node_ids
