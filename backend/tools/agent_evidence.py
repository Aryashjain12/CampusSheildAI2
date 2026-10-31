"""Tool adapter exposing agent evidence functions to controller."""
from agent_network.evidence_tools import (
    read_agent_log,
    read_memory,
    list_permissions,
    list_canary_access,
    list_canary_exfiltrations,
    list_all_events,
    get_provenance_graph
)

__all__ = [
    "read_agent_log",
    "read_memory",
    "list_permissions",
    "list_canary_access",
    "list_canary_exfiltrations",
    "list_all_events",
    "get_provenance_graph"
]
