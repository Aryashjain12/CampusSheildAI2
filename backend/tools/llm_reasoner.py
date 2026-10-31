"""Optional local-only Gemini bridge; returns None unless explicitly configured."""
import json, os
_disabled = False

def classify_with_llm(host, asset, vuln, logs, packet_metadata=None):
    global _disabled
    if not os.environ.get("GEMINI_API_KEY") or _disabled:
        return None
    try:
        from dotenv import load_dotenv
        load_dotenv()
        from google import genai
        from pydantic import BaseModel
        class Outcome(BaseModel):
            outcome: str
            explanation: str
        evidence = {"host":host,"asset":asset,"vulnerability":vuln,"logs":logs,"packet_metadata":packet_metadata or []}
        prompt = ("You are a security analyst. Analyze this synthetic campus SOC case. "
                  "Read negation and event order carefully. Return outcome succeeded, contained, or no_evidence, "
                  "with concise explanation. Never request or execute actions. Evidence:\n" + json.dumps(evidence))
        client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        response = client.models.generate_content(model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"), contents=prompt,
            config={"response_mime_type":"application/json", "response_schema":Outcome})
        result = json.loads(response.text)
        if result.get("outcome") not in {"succeeded","contained","no_evidence"}: return None
        return result
    except Exception:
        _disabled = True
        return None
