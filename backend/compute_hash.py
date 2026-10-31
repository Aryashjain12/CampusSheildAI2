import json
import hashlib

with open("data/scenarios_dataset.json", "r", encoding="utf-8") as f:
    data = json.load(f)

locked = sorted([s for s in data if s.get("split") == "locked"], key=lambda x: x["scenario_id"])
canonical = "|".join(f"{s['scenario_id']}:{s['payload']}" for s in locked)
h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
print(f"LOCKED_SPLIT_HASH = '{h}'")
print(f"Total locked scenarios: {len(locked)}")
