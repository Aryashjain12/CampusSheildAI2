import json
from pathlib import Path
DATA = Path(__file__).resolve().parents[1] / "data"
def check_vulnerability(software, version):
    for item in json.loads((DATA / "cve_kb.json").read_text(encoding="utf-8")):
        if item["software"] == software and version in item["affected_versions"]:
            return item
    return None
