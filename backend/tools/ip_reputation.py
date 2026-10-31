import json
from pathlib import Path
DATA = Path(__file__).resolve().parents[1] / "data"
def get_ip_reputation(ip):
    for item in json.loads((DATA / "trusted_sources.json").read_text(encoding="utf-8")):
        if item["ip"] == ip:
            return item
    return None
