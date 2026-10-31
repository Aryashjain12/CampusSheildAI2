"""Phase 3 tests: Scenario generator, dataset loading, and ground truth validity."""
from pathlib import Path
import json
from collections import Counter
from agent_network.scenarios.generator import generate_scenarios, save_scenarios_dataset, FIXED_SEED
from agent_network.scenarios.runner import ScenarioRunner, run_benchmark


def test_generator_reproducibility():
    s1 = generate_scenarios(count=40, seed=FIXED_SEED)
    s2 = generate_scenarios(count=40, seed=FIXED_SEED)
    assert s1 == s2, "Generator with fixed seed must be 100% reproducible for Member C's evaluation harness"


def test_tuning_locked_split():
    dataset = generate_scenarios(count=80, seed=FIXED_SEED)
    tuning = [s for s in dataset if s["split"] == "tuning"]
    locked = [s for s in dataset if s["split"] == "locked"]

    assert len(dataset) == 80
    assert len(tuning) == 56  # 70% of 80
    assert len(locked) == 24  # 30% of 80


def test_scenario_categories_and_entry_agents_diversity():
    """Verify admin bulk-requests exist and all four agents serve as entry points."""
    dataset = generate_scenarios(count=80, seed=FIXED_SEED)
    categories = Counter(s["category"] for s in dataset)
    entry_agents = Counter(s["entry_agent"] for s in dataset)

    # Gap 1: Admin bulk requests must exist
    assert "admin_bulk_request" in categories
    assert categories["admin_bulk_request"] >= 4

    # Gap 5: All 4 agents must be tested as entry agents
    for agent in ["helpdesk", "student_support", "library", "finance"]:
        assert agent in entry_agents
        assert entry_agents[agent] >= 4


def test_scenario_validity_all_pass_ground_truth():
    """Strict 4-way ground truth verification: states, patient zero, exposed, and exfiltrated."""
    summary = run_benchmark()
    assert summary["total_scenarios"] == 80
    assert summary["passed"] == 80
    assert summary["pass_rate"] == 1.0
    assert summary["patient_zero_accuracy"] == 1.0
    assert summary["per_agent_state_accuracy"] == 1.0
    assert summary["records_exposed_accuracy"] == 1.0
    assert summary["records_exfiltrated_accuracy"] == 1.0


def test_member_c_can_load_dataset():
    p = Path(__file__).resolve().parents[1] / "data" / "scenarios_dataset.json"
    assert p.exists()
    data = json.loads(p.read_text(encoding="utf-8"))
    assert len(data) >= 60  # Document specified 60 to 100 scenarios
    assert "scenario_id" in data[0]
    assert "patient_zero" in data[0]
    assert "expected_states" in data[0]
    assert "split" in data[0]


LOCKED_SPLIT_HASH = "272a6c1760c24a1402e84a9f532eb7201d02af496764392740f093270aca78a6"


def test_locked_split_is_unchanged():
    """Guard: the 30% locked set must never be edited after tuning starts."""
    import hashlib
    p = Path(__file__).resolve().parents[1] / "data" / "scenarios_dataset.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    locked = sorted([s for s in data if s.get("split") == "locked"], key=lambda x: x["scenario_id"])
    canonical = "|".join(f"{s['scenario_id']}:{s['payload']}" for s in locked)
    assert len(locked) == 24
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == LOCKED_SPLIT_HASH, (
        "Locked split changed. Do not tune on or edit the locked scenarios."
    )
