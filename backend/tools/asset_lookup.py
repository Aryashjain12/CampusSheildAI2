import json
from pathlib import Path
DATA = Path(__file__).resolve().parents[1] / "data"
def get_asset(host_id):
    for asset in json.loads((DATA / "assets.json").read_text(encoding="utf-8")):
        if asset["host_id"] == host_id:
            return asset
    return None
