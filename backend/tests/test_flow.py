from fastapi.testclient import TestClient
from app.main import app
from app import store

client = TestClient(app)


def setup_function():
    store.INCIDENTS.clear()
    store.AUDIT.clear()
    store.SIMULATED_QUARANTINE.clear()
    store.INVESTIGATIONS.clear()
    from pathlib import Path
    firewall_state = Path(__file__).resolve().parents[1] / "data" / "firewall_state.json"
    firewall_state.write_text("{\"blocked\": []}", encoding="utf-8")


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_end_to_end_port_scan_simulated_containment():
    incident_response = client.post("/demo/port-scan")
    assert incident_response.status_code == 200
    incident = incident_response.json()
    incident_id = incident["id"]
    assert incident["severity"] == "high"
    assert incident["verdict"] is not None
    assert incident["investigation"]["steps"]

    response = client.post(f"/incidents/{incident_id}/respond")
    assert response.status_code == 200
    assert response.json()["status"] == "simulated"
    assert "no real network was changed" in response.json()["message"]

    verification = client.post(f"/incidents/{incident_id}/verify")
    assert verification.status_code == 200
    assert verification.json()["passed"] is True

    final_incident = client.get(f"/incidents/{incident_id}").json()
    assert final_incident["status"] == "resolved"
    assert final_incident["verification"] == "passed"


def test_low_signal_does_not_create_incident():
    response = client.post("/events", json={
        "event_type": "port_scan",
        "source_id": "benign-lab-client",
        "features": {"unique_destination_ports": 2, "connection_attempts": 3}
    })
    assert response.status_code == 200
    assert response.json()["alert"] is False


def test_unknown_incident_is_404():
    response = client.post("/incidents/not-a-real-id/respond")
    assert response.status_code == 404


def test_investigation_endpoint_returns_auditable_trace():
    created = client.post("/demo/brute-force")
    assert created.status_code == 200
    incident_id = created.json()["id"]
    response = client.get(f"/incidents/{incident_id}/investigation")
    assert response.status_code == 200
    case = response.json()
    assert case["verdict"]
    assert case["evidence"]["self_consistency_check"]["checks"]
    assert any(step["label"] == "SELF-CHECK" for step in case["steps"])


def test_reconsider_requires_note_and_keeps_simulated_scope():
    created = client.post("/demo/port-scan").json()
    incident_id = created["id"]
    response = client.post(f"/incidents/{incident_id}/reconsider", json={"note": "Please re-check this synthetic case"})
    assert response.status_code == 200
    assert any("Please re-check this synthetic case" in step["detail"] for step in response.json()["steps"])
    assert response.json()["verdict"] == created["verdict"]  # non-breach verdict is not auto-overridden
