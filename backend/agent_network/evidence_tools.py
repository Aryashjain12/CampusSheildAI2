"""Agent evidence tools for Member A's investigation controller.

Allows the SOCrates controller to inspect:
- read agent log
- read memory
- list permissions
- list canary access
- get provenance graph
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from agent_network.shared_memory import SharedMemory, MessageBus
from agent_network.permissions import PermissionConfig, DEFAULT_CONFIG
from agent_network.decoys_and_canaries import CanaryAccessTracker, DecoyEngine
from agent_network.models import CommonEvent

# Global active network context singleton
_GLOBAL_AGENTS: Dict[str, Any] = {}
_GLOBAL_MEMORY: Optional[SharedMemory] = None
_GLOBAL_BUS: Optional[MessageBus] = None
_GLOBAL_CANARY_TRACKER: Optional[CanaryAccessTracker] = None
_GLOBAL_DECOY_ENGINE: Optional[DecoyEngine] = None
_GLOBAL_EVENT_BUS: List[CommonEvent] = []


def register_global_network(
    agents: Dict[str, Any],
    memory: SharedMemory,
    bus: MessageBus,
    canary_tracker: CanaryAccessTracker,
    decoy_engine: DecoyEngine,
    event_bus: List[CommonEvent]
):
    global _GLOBAL_AGENTS, _GLOBAL_MEMORY, _GLOBAL_BUS, _GLOBAL_CANARY_TRACKER, _GLOBAL_DECOY_ENGINE, _GLOBAL_EVENT_BUS
    _GLOBAL_AGENTS = agents
    _GLOBAL_MEMORY = memory
    _GLOBAL_BUS = bus
    _GLOBAL_CANARY_TRACKER = canary_tracker
    _GLOBAL_DECOY_ENGINE = decoy_engine
    _GLOBAL_EVENT_BUS = event_bus


def read_agent_log(agent_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve audit action log for a given agent or all agents."""
    if agent_name:
        agent = _GLOBAL_AGENTS.get(agent_name.lower().replace(" ", "_"))
        if agent:
            return agent.get_action_log()
        return []
    
    logs = []
    for name, agent in _GLOBAL_AGENTS.items():
        logs.extend([{"agent": name, **entry} for entry in agent.get_action_log()])
    return logs


def read_memory(include_quarantined: bool = False) -> List[Dict[str, Any]]:
    """Retrieve current entries stored in shared agent memory."""
    if not _GLOBAL_MEMORY:
        return []
    entries = _GLOBAL_MEMORY.read_all(include_quarantined=include_quarantined)
    return [e.model_dump() for e in entries]


def list_permissions(agent_name: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve permission boundaries (allowed and forbidden tools) for agents."""
    config = DEFAULT_CONFIG
    if agent_name:
        rule = config.agents.get(agent_name.lower().replace(" ", "_"))
        return {agent_name: rule.model_dump()} if rule else {}
    return {k: v.model_dump() for k, v in config.agents.items()}


def list_canary_access() -> List[Dict[str, Any]]:
    """Retrieve provable canary access logs showing which agents touched canaries."""
    if not _GLOBAL_CANARY_TRACKER:
        return []
    return _GLOBAL_CANARY_TRACKER.get_access_log()


def list_canary_exfiltrations() -> List[Dict[str, Any]]:
    """Retrieve confirmed canary exfiltrations."""
    if not _GLOBAL_CANARY_TRACKER:
        return []
    return _GLOBAL_CANARY_TRACKER.get_exfiltrated()


def list_all_events() -> List[Dict[str, Any]]:
    """Retrieve all common security events emitted across the agent network."""
    return [e.model_dump() for e in _GLOBAL_EVENT_BUS]


def get_provenance_graph() -> Dict[str, Any]:
    """Returns nodes and edges representing agent interactions, memory reads/writes, and messages."""
    nodes = []
    edges = []

    # Agents
    for name in ["helpdesk", "library", "finance", "student_support"]:
        state = _GLOBAL_AGENTS[name].state if name in _GLOBAL_AGENTS else "clean"
        nodes.append({"id": f"agent:{name}", "type": "agent", "name": name, "state": state})

    # Memory entries
    if _GLOBAL_MEMORY:
        for entry in _GLOBAL_MEMORY.read_all(include_quarantined=True):
            nodes.append({
                "id": f"memory:{entry.id}",
                "type": "memory",
                "author": entry.agent,
                "quarantined": entry.quarantined
            })
            edges.append({
                "source": f"agent:{entry.agent}",
                "target": f"memory:{entry.id}",
                "relation": "writes_memory"
            })

    # Bus messages
    if _GLOBAL_BUS:
        for pe in _GLOBAL_BUS.get_provenance_edges():
            edges.append({
                "source": f"agent:{pe['from']}",
                "target": f"agent:{pe['to']}",
                "relation": "sends_message",
                "message_id": pe["message_id"]
            })

    return {"nodes": nodes, "edges": edges}
