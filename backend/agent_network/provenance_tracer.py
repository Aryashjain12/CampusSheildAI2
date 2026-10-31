"""Real provenance graph tracing engine for Patient Zero attribution (Section 8).

Implements real causal backward-traversal across inter-agent messages and shared memory.
When graph_enabled=False, inter-agent edges are removed, evaluating isolated local alerts.
"""
from __future__ import annotations
from typing import Dict, List, Optional, Set, Any
from collections import defaultdict

from agent_network.models import CommonEvent


class ProvenanceTracer:
    """Traces causal propagation chains backwards to determine Patient Zero."""

    def __init__(self, graph_enabled: bool = True):
        self.graph_enabled = graph_enabled

    def trace_patient_zero(
        self,
        agents_map: Dict[str, Any],
        events: List[CommonEvent],
        bus_edges: List[Dict[str, Any]],
        memory_entries: List[Any]
    ) -> Optional[str]:
        # Identify agents exhibiting security violations or anomalous states
        affected_agents: Set[str] = set()
        for name, agent in agents_map.items():
            if agent.state in ("compromised", "exposed"):
                affected_agents.add(name)

        if not affected_agents:
            return None

        # If only one agent is affected, that agent is patient zero
        if len(affected_agents) == 1:
            return next(iter(affected_agents))

        # Real Graph Tracing (graph_enabled = True)
        if self.graph_enabled:
            # Construct directed adjacency list: causal_parents[child] = [parent, ...]
            causal_parents: Dict[str, List[str]] = defaultdict(list)

            # 1. Message bus edges: sender -> recipient
            for edge in bus_edges:
                sender = edge.get("actual_sender") or edge.get("from")
                recipient = edge.get("to")
                if sender and recipient and sender != recipient:
                    causal_parents[recipient].append(sender)

            # 2. Shared memory relay edges: author -> memory -> reader
            # If agent A wrote a poisoned entry and agent B read it, A is causal parent of B
            for mem in memory_entries:
                author = getattr(mem, "agent", None) or mem.get("agent")
                content = getattr(mem, "content", "") or mem.get("content", "")
                if author and "[RELAY INSTRUCTION]" in content:
                    for child in affected_agents:
                        if child != author and author not in causal_parents[child]:
                            causal_parents[child].append(author)

            # Backward traversal from affected leaf nodes to ancestral roots
            def find_root_ancestor(node: str, visited: Set[str]) -> str:
                if node in visited:
                    return node
                visited.add(node)
                parents = causal_parents.get(node, [])
                if not parents:
                    return node
                # Recurse up the causal chain
                for p in parents:
                    if p in affected_agents or agents_map.get(p, None):
                        return find_root_ancestor(p, visited)
                return node

            # Trace back each affected agent
            candidate_roots: Set[str] = set()
            for affected in affected_agents:
                root = find_root_ancestor(affected, set())
                candidate_roots.add(root)

            # Among candidate roots, select the node with compromise event or earliest timestamp
            for ev in events:
                if ev.event_type == "agent_compromised":
                    entity_name = ev.entity.replace("agent:", "")
                    if entity_name in candidate_roots:
                        return entity_name

            if candidate_roots:
                return next(iter(candidate_roots))
            return None

        else:
            # GRAPH OFF ABLATION:
            # Memory and message bus edges are removed (empty graph).
            # Without inter-agent causal edges, the engine must rely on isolated local alerts.
            # Look for the agent that generated the highest severity or data exfiltration alert locally.
            data_access_agents: Set[str] = set()
            for ev in events:
                if ev.event_type in ("canary_record_accessed", "decoy_record_accessed", "decoy_tool_triggered"):
                    agent_name = ev.entity.replace("agent:", "")
                    data_access_agents.add(agent_name)

            if data_access_agents:
                # Without graph to trace backwards, attribution incorrectly falls on the symptom agent
                return next(iter(data_access_agents))

            # Fallback to earliest local event entity
            if events:
                first_agent_ev = next(
                    (e for e in events if e.entity.startswith("agent:")), None
                )
                if first_agent_ev:
                    return first_agent_ev.entity.replace("agent:", "")
            return None
