"""Integration tests for Member B API endpoints."""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_api_demo_agent_attack():
    response = client.post("/demo/agent-attack")
    assert response.status_code == 200
    data = response.json()
    assert "incident" in data
    assert "attack_summary" in data
    assert data["attack_summary"]["patient_zero"] == "helpdesk"
    assert "spread_strip" in data["attack_summary"]
    assert "Library: clean" in data["attack_summary"]["spread_strip"] or "library: clean" in data["attack_summary"]["spread_strip"]


def test_api_get_scenarios():
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 80
    assert len(data["scenarios"]) == 80

    # Test filtering by split
    res_tuning = client.get("/api/scenarios?split=tuning")
    assert res_tuning.status_code == 200
    assert res_tuning.json()["total"] == 56

    res_locked = client.get("/api/scenarios?split=locked")
    assert res_locked.status_code == 200
    assert res_locked.json()["total"] == 24


def test_api_run_scenarios_benchmark():
    response = client.post("/api/scenarios/benchmark", json={"split": "tuning", "decoys_enabled": True})
    assert response.status_code == 200
    data = response.json()
    assert data["total_scenarios"] == 56
    assert data["pass_rate"] == 1.0
    assert data["patient_zero_accuracy"] == 1.0


def test_api_agent_provenance_and_permissions():
    prov = client.get("/api/agent-network/provenance")
    assert prov.status_code == 200
    assert "nodes" in prov.json()
    assert "edges" in prov.json()

    perms = client.get("/api/agent-network/permissions")
    assert perms.status_code == 200
    assert "helpdesk" in perms.json()
    assert "finance" in perms.json()
