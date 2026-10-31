"""Base class for scripted campus agents with mandatory permission checks and event emission."""
from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime

from agent_network.models import CommonEvent, ToolCallResult, AgentStateName
from agent_network.permissions import PermissionConfig, DEFAULT_CONFIG
from agent_network.shared_memory import SharedMemory, MessageBus
from agent_network.decoys_and_canaries import DecoyEngine, CanaryAccessTracker
from agent_network.fixture_data import StudentDatabase, STUDENT_DB


class BaseAgent:
    """Base class for scripted agents.
    
    Ensures every tool call passes through the permission engine, audits events,
    and updates the agent's internal state.
    """

    def __init__(
        self,
        name: str,
        role_description: str,
        permission_config: Optional[PermissionConfig] = None,
        shared_memory: Optional[SharedMemory] = None,
        message_bus: Optional[MessageBus] = None,
        decoy_engine: Optional[DecoyEngine] = None,
        canary_tracker: Optional[CanaryAccessTracker] = None,
        student_db: Optional[StudentDatabase] = None,
        event_log: Optional[List[CommonEvent]] = None
    ):
        self.name = name.lower().replace(" ", "_")
        self.display_name = name
        self.role_description = role_description
        self.permission_config = permission_config or DEFAULT_CONFIG
        self.shared_memory = shared_memory or SharedMemory()
        self.message_bus = message_bus or MessageBus()
        self.decoy_engine = decoy_engine or DecoyEngine()
        self.canary_tracker = canary_tracker or CanaryAccessTracker()
        self.student_db = student_db or STUDENT_DB
        self.event_log = event_log if event_log is not None else []
        self.state: AgentStateName = "clean"
        self.guardrail_enabled: bool = False
        self.audit_override_token: Optional[str] = None
        self._action_log: List[Dict[str, Any]] = []
        self._tool_handlers: Dict[str, Callable[..., Any]] = {}

    def set_defense(self, defense: dict | Any | None):
        """Set explicit defense parameters for the agent without inspecting scenario labels."""
        if not defense:
            self.guardrail_enabled = False
            self.audit_override_token = None
            return
        if hasattr(defense, "injection_guardrail"):
            self.guardrail_enabled = bool(defense.injection_guardrail)
            self.audit_override_token = defense.audit_override_token
        elif isinstance(defense, dict):
            self.guardrail_enabled = bool(defense.get("injection_guardrail", False))
            self.audit_override_token = defense.get("audit_override_token")

    def register_tool(self, tool_name: str, handler: Callable[..., Any]):
        self._tool_handlers[tool_name] = handler

    def log_event(self, event: CommonEvent):
        if not any(e.id == event.id for e in self.event_log):
            self.event_log.append(event)

    def execute_tool(self, tool_name: str, **kwargs) -> ToolCallResult:
        """Call a tool with mandatory permission and decoy checks."""
        # Check Decoy Trap first
        decoy_evt = self.decoy_engine.check_decoy_tool(self.name, tool_name, kwargs)
        if decoy_evt:
            self.log_event(decoy_evt)

        # Check Permission
        allowed, perm_event = self.permission_config.check_and_create_event(self.name, tool_name, kwargs)
        self.log_event(perm_event)

        from datetime import timezone
        self._action_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool_name,
            "kwargs": kwargs,
            "allowed": allowed
        })

        if not allowed:
            # Mark agent as exposed or compromised based on violation
            if self.state in ("clean", "attacked_but_resisted"):
                self.state = "exposed"
            return ToolCallResult(
                agent=self.name,
                tool_name=tool_name,
                allowed=False,
                success=False,
                error=f"Permission denied: agent '{self.name}' is forbidden from using tool '{tool_name}'",
                event=perm_event
            )

        handler = self._tool_handlers.get(tool_name)
        if not handler:
            return ToolCallResult(
                agent=self.name,
                tool_name=tool_name,
                allowed=True,
                success=False,
                error=f"Tool '{tool_name}' registered in permissions but has no local handler"
            )

        try:
            result = handler(**kwargs)
            return ToolCallResult(
                agent=self.name,
                tool_name=tool_name,
                allowed=True,
                success=True,
                data=result,
                event=perm_event
            )
        except Exception as e:
            return ToolCallResult(
                agent=self.name,
                tool_name=tool_name,
                allowed=True,
                success=False,
                error=str(e),
                event=perm_event
            )

    def send_bus_message(
        self, recipient: str, content: str, impersonate_as: Optional[str] = None
    ):
        msg, evt = self.message_bus.send(
            sender=self.name,
            recipient=recipient,
            content=content,
            impersonated_from=impersonate_as
        )
        self.log_event(evt)
        return msg

    def check_inbox(self) -> list:
        return self.message_bus.receive(self.name)

    def write_memory(self, content: str, metadata: dict | None = None):
        entry, evt = self.shared_memory.write(self.name, content, metadata)
        self.log_event(evt)
        return entry

    def read_memory(self) -> list:
        return self.shared_memory.read_all(reader_agent=self.name)

    def get_action_log(self) -> list[dict]:
        return list(self._action_log)
