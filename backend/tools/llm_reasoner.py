"""Optional local-only advisory bridge.

Provides explain-only advisory context for the deterministic SOCrates path.
It must never influence verdict, confidence, action decisions, or blocking.

Two providers are supported behind the same advisory boundary:

- Gemini, configured through:
    GEMINI_API_KEY=...
    GEMINI_MODEL=gemini-2.5-flash

- NVIDIA Nemotron, configured through:
    NVIDIA_API_KEY=...
    NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
    NVIDIA_MODEL=nvidia/nemotron-3.5-lightning-30b-a3b

NVIDIA is preferred when NVIDIA_API_KEY is set. If neither provider is
configured, classify_with_llm returns None and the deterministic
investigation continues normally.

NVIDIA credentials are never printed or logged. The existing .env setup is
not assumed to be present in this repository; if it is missing, the bridge
is silently disabled. For configuration, copy backend/.env.example to a
local backend/.env and fill in the relevant keys, or set the environment
variables in the deployment environment.
"""


def get_advisory_schema():
    """Return the advisory schema used for structured validation.

    This is used by tests and documentation to describe the expected shape.
    """
    from pydantic import BaseModel

    class AdvisorySchema(BaseModel):
        explanation: str
        risk_observations: list[str] = []
        recommendations: list[str] = []

        model_config = {"extra": "forbid"}

    return AdvisorySchema
import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

_DISABLED = False


class Advisory(BaseModel):
    explanation: str
    risk_observations: list[str] = []
    recommendations: list[str] = []

    model_config = {"extra": "forbid"}


def classify_with_llm(host, asset, vuln, logs, packet_metadata=None):
    """Return optional explain-only advisory context, or None."""
    global _DISABLED

    try:
        from dotenv import load_dotenv

        env_file = Path(__file__).resolve().parents[1] / ".env"
        load_dotenv(dotenv_path=env_file, override=False)

        if _DISABLED:
            return None

        providers = []
        if os.environ.get("NVIDIA_API_KEY"):
            providers.append(_call_nemotron)
        if os.environ.get("GEMINI_API_KEY"):
            providers.append(_call_gemini)

        for provider in providers:
            try:
                result = provider(host, asset, vuln, logs, packet_metadata)
                validated = _validate_advisory_payload(result)
                if validated is not None:
                    return validated
            except Exception:
                continue

        return None
    except Exception:
        return None


def _build_evidence(host, asset, vuln, logs, packet_metadata):
    return {
        "host": host,
        "asset": asset,
        "vulnerability": vuln,
        "logs": logs,
        "packet_metadata": packet_metadata or [],
    }


def _call_gemini(host, asset, vuln, logs, packet_metadata):
    from dotenv import load_dotenv

    load_dotenv()
    try:
        from google import genai
    except ImportError:
        raise RuntimeError("Google GenAI is not installed")

    if not os.environ.get("GEMINI_API_KEY"):
        raise RuntimeError("GEMINI_API_KEY is not configured")

    evidence = _build_evidence(host, asset, vuln, logs, packet_metadata)
    prompt = (
        "You are a security analyst providing optional advisory analysis for a synthetic campus SOC case. "
        "Do not classify the incident outcome, select a verdict, authorize containment, or request actions. "
        "Return a concise explanation, risk_observations, and investigation recommendations only. Evidence:\n"
        + json.dumps(evidence)
    )
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    response = client.models.generate_content(
        model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        contents=prompt,
        config={
            "response_mime_type": "application/json",
            "response_schema": Advisory,
        },
    )
    return _validate_advisory(response.text)


def _call_nemotron(host, asset, vuln, logs, packet_metadata):
    import httpx

    base = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
    model = os.environ.get("NVIDIA_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
    evidence = _build_evidence(host, asset, vuln, logs, packet_metadata)
    prompt = (
        "You are a security analyst providing optional advisory analysis for a synthetic campus SOC case. "
        "Do not classify the incident outcome, select a verdict, authorize containment, or request actions. "
        "Return a concise explanation, risk_observations, and investigation recommendations only. Evidence:\n"
        + json.dumps(evidence)
    )
    try:
        timeout_seconds = float(os.environ.get("NVIDIA_TIMEOUT_SECONDS", "5"))
        with httpx.Client(timeout=max(0.1, min(timeout_seconds, 30.0))) as client:
            response = client.post(
                f"{base}/chat/completions",
                headers={
                    "Authorization": f"Bearer {os.environ['NVIDIA_API_KEY']}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.0,
                    "max_tokens": 1024,
                    "response_format": {"type": "json_object"},
                },
            )
        response.raise_for_status()
        body = response.json()
        content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not content:
            return None
        return _validate_advisory(content)
    except Exception as exc:
        raise RuntimeError("NVIDIA Nemotron advisory unavailable") from exc


def enable_nemotron_advisory():
    """Expose NVIDIA Nemotron as an optional advisory provider.

    Calling this function enables the NVIDIA path when NVIDIA_API_KEY is set.
    It does not change any other behaviour.
    """
    global _DISABLED
    _DISABLED = False


def is_nemotron_advisory_enabled() -> bool:
    return bool(os.environ.get("NVIDIA_API_KEY")) and not _DISABLED


# Public advisory contract for the controller.

def get_advisory(host, asset, vuln, logs, packet_metadata=None):
    """Return optional advisory context, or None.

    This is the stable entry point for the controller. It preserves the
    existing Gemini path when GEMINI_API_KEY is set, prefers NVIDIA Nemotron
    when NVIDIA_API_KEY is set, and otherwise returns None.
    """
    return classify_with_llm(host, asset, vuln, logs, packet_metadata)


def disable_advisory():
    """Disable the advisory bridge after a failure.

    This is called by the controller when the advisory cannot be obtained.
    """
    global _DISABLED
    _DISABLED = True


def is_advisory_provider_available() -> bool:
    """Return whether any advisory provider configuration is present.

    Used by the controller to decide whether to attempt an advisory call.
    """
    return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("NVIDIA_API_KEY"))


def _validate_advisory(text):
    if not isinstance(text, str):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return _validate_advisory_payload(parsed)


def _validate_advisory_payload(payload: Any) -> dict[str, Any] | None:
    """Return only the approved advisory fields from a provider response."""
    if not isinstance(payload, dict):
        return None
    explanation = payload.get("explanation")
    observations = payload.get("risk_observations")
    recommendations = payload.get("recommendations")
    if not isinstance(explanation, str) or not explanation.strip():
        return None
    if not isinstance(observations, list) or not all(isinstance(item, str) for item in observations):
        return None
    if not isinstance(recommendations, list) or not all(isinstance(item, str) for item in recommendations):
        return None
    return {
        "explanation": explanation.strip(),
        "risk_observations": observations,
        "recommendations": recommendations,
    }
