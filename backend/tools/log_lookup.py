import json
from pathlib import Path
DATA = Path(__file__).resolve().parents[1] / "data"
def get_logs(host_id):
    return json.loads((DATA / "logs.json").read_text(encoding="utf-8")).get(host_id, [])
