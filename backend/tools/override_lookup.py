import json
from pathlib import Path
DATA = Path(__file__).resolve().parents[1] / "data"
def get_override(alert_id):
    for item in json.loads((DATA / "human_overrides.json").read_text(encoding="utf-8")):
        if item["alert_id"] == alert_id:
            return item
    return None
