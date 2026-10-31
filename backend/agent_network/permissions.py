"""Permission engine and configuration based on CampusShield AI 2.0 Section 6."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, List, Set
from pydantic import BaseModel, Field

from agent_network.models import CommonEvent

# Section 6 Permission Definition
DEFAULT_PERMISSION_TABLE = {
    "helpdesk": {
        "allowed": ["read_tickets", "reply_ticket", "post_shared_memory", "read_shared_memory"],
        "not_allowed": [
            "get_fee_record",
            "lookup_student",
            "lookup_own_student",
            "bulk_lookup",
            "export_records",
            "export_all_records",
            "fake_export_tool"
        ],
        "description": "Helpdesk helper: can read tickets and post/read shared memory, forbidden from fee or student records."
    },
    "library": {
        "allowed": ["catalogue_search"],
        "not_allowed": [
            "get_fee_record",
            "lookup_student",
            "lookup_own_student",
            "bulk_lookup",
            "export_records",
            "export_all_records",
            "post_shared_memory",
            "fake_export_tool"
        ],
        "description": "Library helper: catalogue search only, forbidden from any student data."
    },
    "finance": {
        "allowed": ["get_fee_record", "read_shared_memory", "post_shared_memory"],
        "not_allowed": [
            "export_all_records",
            "export_records",
            "bulk_lookup",
            "catalogue_search",
            "fake_export_tool"
        ],
        "description": "Finance helper: read fee records, forbidden from bulk export of all records."
    },
    "student_support": {
        "allowed": ["lookup_own_student", "read_shared_memory", "post_shared_memory"],
        "not_allowed": [
            "bulk_lookup",
            "get_fee_record",
            "export_all_records",
            "export_records",
            "fake_export_tool"
        ],
        "description": "Student support helper: single student lookup for assigned case, forbidden from bulk lookups and fee records."
    }
}


class AgentPermissionRule(BaseModel):
    allowed: List[str] = Field(default_factory=list)
    not_allowed: List[str] = Field(default_factory=list)
    description: str = ""


class PermissionConfig(BaseModel):
    agents: Dict[str, AgentPermissionRule] = Field(default_factory=dict)

    def is_allowed(self, agent_name: str, tool_name: str) -> bool:
        agent_key = agent_name.lower().replace(" ", "_")
        rule = self.agents.get(agent_key)
        if not rule:
            return False
        # If explicitly in not_allowed, forbidden
        if tool_name in rule.not_allowed:
            return False
        # If in allowed list, permitted
        return tool_name in rule.allowed

    def check_and_create_event(
        self, agent_name: str, tool_name: str, arguments: dict | None = None
    ) -> tuple[bool, CommonEvent]:
        allowed = self.is_allowed(agent_name, tool_name)
        agent_key = agent_name.lower().replace(" ", "_")
        rule = self.agents.get(agent_key)
        args_clean = arguments or {}

        if allowed:
            event = CommonEvent(
                source=f"permission_guard:{agent_key}",
                entity=f"agent:{agent_key}",
                event_type="tool_call_authorized",
                evidence={
                    "tool": tool_name,
                    "arguments": args_clean,
                    "policy": "allowed_by_role",
                    "allowed_tools": rule.allowed if rule else []
                },
                severity="info",
                confidence=1.0,
                related_entities=[f"agent:{agent_key}", f"tool:{tool_name}"]
            )
        else:
            event = CommonEvent(
                source=f"permission_guard:{agent_key}",
                entity=f"agent:{agent_key}",
                event_type="permission_denied",
                evidence={
                    "tool": tool_name,
                    "arguments": args_clean,
                    "policy": "boundary_violation",
                    "reason": f"Agent {agent_name} attempted forbidden tool '{tool_name}'",
                    "forbidden_tools": rule.not_allowed if rule else []
                },
                severity="high",
                confidence=0.98,
                related_entities=[f"agent:{agent_key}", f"tool:{tool_name}"]
            )
        return allowed, event


def load_permission_config(config_path: Path | str | None = None) -> PermissionConfig:
    """Load permission config from JSON file or default table."""
    if config_path:
        p = Path(config_path)
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            return PermissionConfig.model_validate(data)
    
    # Check default path under data/
    default_p = Path(__file__).resolve().parents[1] / "data" / "agent_permissions.json"
    if default_p.exists():
        try:
            data = json.loads(default_p.read_text(encoding="utf-8"))
            return PermissionConfig.model_validate(data)
        except Exception:
            pass

    # Build from DEFAULT_PERMISSION_TABLE
    cfg = PermissionConfig(agents={k: AgentPermissionRule(**v) for k, v in DEFAULT_PERMISSION_TABLE.items()})
    # Save default config file to data directory
    try:
        default_p.parent.mkdir(parents=True, exist_ok=True)
        default_p.write_text(cfg.model_dump_json(indent=2), encoding="utf-8")
    except Exception:
        pass
    return cfg


DEFAULT_CONFIG = load_permission_config()
