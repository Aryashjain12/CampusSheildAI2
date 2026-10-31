"""Unit tests for the optional provider-independent advisory boundary."""
from tools import llm_reasoner


def _args():
    return ("host", {"software": "demo"}, None, [])


def test_nemotron_advisory_success_strips_attempted_verdict_manipulation(monkeypatch):
    monkeypatch.setattr(llm_reasoner, "_DISABLED", False)
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(llm_reasoner, "_call_nemotron", lambda *args: {
        "explanation": "Review the authentication evidence.",
        "risk_observations": ["Repeated authentication failures"],
        "recommendations": ["Collect packet metadata"],
        "verdict": "confirmed_breach",
        "outcome": "succeeded",
        "confidence": 1.0,
        "response_instruction": "block now",
    })

    result = llm_reasoner.classify_with_llm(*_args())

    assert result == {
        "explanation": "Review the authentication evidence.",
        "risk_observations": ["Repeated authentication failures"],
        "recommendations": ["Collect packet metadata"],
    }


def test_unavailable_provider_returns_none(monkeypatch):
    monkeypatch.setattr(llm_reasoner, "_DISABLED", False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    assert llm_reasoner.classify_with_llm(*_args()) is None


def test_malformed_provider_response_is_ignored(monkeypatch):
    monkeypatch.setattr(llm_reasoner, "_DISABLED", False)
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    monkeypatch.setattr(llm_reasoner, "_call_nemotron", lambda *args: {
        "explanation": "Missing required advisory arrays"
    })

    assert llm_reasoner.classify_with_llm(*_args()) is None


def test_nvidia_failure_uses_configured_gemini_fallback(monkeypatch):
    monkeypatch.setattr(llm_reasoner, "_DISABLED", False)
    monkeypatch.setenv("NVIDIA_API_KEY", "nvidia-test-key")
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")
    monkeypatch.setattr(llm_reasoner, "_call_nemotron", lambda *args: (_ for _ in ()).throw(RuntimeError("timeout")))
    monkeypatch.setattr(llm_reasoner, "_call_gemini", lambda *args: {
        "explanation": "Fallback advisory.", "risk_observations": [], "recommendations": []
    })

    assert llm_reasoner.classify_with_llm(*_args())["explanation"] == "Fallback advisory."
