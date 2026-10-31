"""Regression tests for the deterministic SOCrates decision boundary."""
import json
from pathlib import Path
import time

import pytest

from agent import controller
from tools.firewall import is_blocked


FIREWALL_STATE = Path(__file__).resolve().parents[1] / "data" / "firewall_state.json"


def setup_function():
    controller.reset_session_memory()
    FIREWALL_STATE.write_text(json.dumps({"blocked": []}), encoding="utf-8")


def _alert(source="llm-regression-source"):
    return {
        "alert_id": "LLM-REGRESSION",
        "signature": "Synthetic investigation",
        "severity": "high",
        "source_ip": source,
        "dest_host": "campus-lab-login",
    }


def test_llm_succeeded_cannot_override_deterministic_no_evidence(monkeypatch):
    monkeypatch.setattr(controller, "classify_with_llm", lambda *args: {
        "outcome": "succeeded", "explanation": "Incorrect advisory conclusion."
    })

    case = controller.investigate(_alert())

    assert case.verdict == "attempted_but_failed"
    assert not case.actions_taken
    assert not is_blocked("llm-regression-source")


def test_llm_contained_cannot_override_deterministic_succeeded(monkeypatch):
    monkeypatch.setattr(controller, "_classify_logs", lambda logs: "succeeded")
    monkeypatch.setattr(controller, "classify_with_llm", lambda *args: {
        "outcome": "contained", "explanation": "Incorrect advisory conclusion."
    })

    case = controller.investigate(_alert())

    assert case.verdict == "confirmed_breach"
    assert any(action["action"] == "block" for action in case.actions_taken)
    assert is_blocked("llm-regression-source")


def test_llm_failure_does_not_interrupt_deterministic_investigation(monkeypatch):
    def fail(*args):
        raise RuntimeError("LLM unavailable")

    monkeypatch.setattr(controller, "classify_with_llm", fail)

    case = controller.investigate(_alert())

    assert case.verdict == "attempted_but_failed"
    assert any(step["label"] == "REASONING (AI)" for step in case.steps)


def test_llm_cannot_independently_trigger_block(monkeypatch):
    calls = []
    original_block = controller._block

    def track_block(*args):
        calls.append(args)
        return original_block(*args)

    monkeypatch.setattr(controller, "_block", track_block)
    monkeypatch.setattr(controller, "classify_with_llm", lambda *args: {
        "outcome": "succeeded", "explanation": "Block this source."
    })

    case = controller.investigate(_alert())

    assert case.verdict == "attempted_but_failed"
    assert calls == []


def test_llm_timeout_does_not_delay_or_change_deterministic_result(monkeypatch):
    monkeypatch.setattr(controller, "LLM_ADVISORY_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(controller, "classify_with_llm", lambda *args: (time.sleep(0.1), None)[1])

    case = controller.investigate(_alert())

    assert case.verdict == "attempted_but_failed"
    assert any("timed out" in step["detail"] for step in case.steps)
