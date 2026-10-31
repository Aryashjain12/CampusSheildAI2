"""Sandbox-only firewall state. This module never configures a real firewall."""
import json
from pathlib import Path
STATE_FILE = Path(__file__).resolve().parents[1] / "data" / "firewall_state.json"
def _load():
    if not STATE_FILE.exists(): return {"blocked": []}
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))
def _save(data): STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
def block(ip_or_host):
    data=_load()
    if ip_or_host not in data["blocked"]: data["blocked"].append(ip_or_host); _save(data)
    return {"action":"block","target":ip_or_host,"status":"blocked","simulated":True}
def unblock(ip_or_host):
    data=_load()
    if ip_or_host in data["blocked"]: data["blocked"].remove(ip_or_host); _save(data)
    return {"action":"unblock","target":ip_or_host,"status":"unblocked","simulated":True}
def is_blocked(ip_or_host): return ip_or_host in _load()["blocked"]
