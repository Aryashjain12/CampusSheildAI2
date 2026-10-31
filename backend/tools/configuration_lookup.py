import json
from pathlib import Path
DATA = Path(__file__).resolve().parents[1] / "data"
def get_configuration(host_id):
    for item in json.loads((DATA / "configuration.json").read_text(encoding="utf-8")):
        if item["host_id"] == host_id:
            return item
    return None
