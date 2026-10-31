from pathlib import Path


def test_dashboard_uses_central_intelligence_api_endpoints():
    dashboard = (Path(__file__).resolve().parents[1] / "app" / "static" / "index.html").read_text(encoding="utf-8")

    for endpoint in (
        "/api/security-events",
        "/api/evidence",
        "/api/correlations",
        "/api/system/status",
        "/api/system/modules",
    ):
        assert endpoint in dashboard
    assert "Central intelligence API unavailable" in dashboard
    assert "setInterval(refresh,10000)" in dashboard


def test_dashboard_does_not_claim_static_benchmark_results():
    dashboard = (Path(__file__).resolve().parents[1] / "app" / "static" / "index.html").read_text(encoding="utf-8")

    assert 'id="bValPZ">—' in dashboard
    assert 'id="bValState">—' in dashboard
    assert "STATUS UNKNOWN" in dashboard
