"""Shared memory and inter-agent message bus with audit logging and provenance tracing."""
from __future__ import annotations
from typing import List, Dict, Any, Optional
from datetime import datetime

from agent_network.models import CommonEvent, MemoryEntry, BusMessage


class SharedMemory:
    """Shared memory store accessible across collaborative agents.
    
    Each entry tracks: agent, timestamp, content, metadata, and quarantine status.
    """

    def __init__(self, event_bus: Optional[List[CommonEvent]] = None):
        self._entries: List[MemoryEntry] = []
        self._event_bus = event_bus if event_bus is not None else []

    def write(self, agent: str, content: str, metadata: dict | None = None) -> tuple[MemoryEntry, CommonEvent]:
        entry = MemoryEntry(
            agent=agent,
            content=content,
            metadata=metadata or {}
        )
        self._entries.append(entry)

        event = CommonEvent(
            source=f"agent:{agent}",
            entity=f"agent:{agent}",
            event_type="shared_memory_write",
            evidence={
                "memory_id": entry.id,
                "agent": agent,
                "content_preview": content[:120],
                "content_length": len(content),
                "metadata": entry.metadata
            },
            severity="info",
            confidence=1.0,
            related_entities=[f"agent:{agent}", f"memory:{entry.id}"]
        )
        self._event_bus.append(event)
        return entry, event

    def read_all(self, include_quarantined: bool = False, reader_agent: str | None = None) -> list[MemoryEntry]:
        if include_quarantined:
            results = list(self._entries)
        else:
            results = [e for e in self._entries if not e.quarantined]

        if reader_agent:
            event = CommonEvent(
                source=f"agent:{reader_agent}",
                entity=f"agent:{reader_agent}",
                event_type="shared_memory_read",
                evidence={
                    "reader": reader_agent,
                    "entries_count": len(results),
                    "memory_ids": [e.id for e in results]
                },
                severity="info",
                confidence=1.0,
                related_entities=[f"agent:{reader_agent}"]
            )
            self._event_bus.append(event)
        return results

    def get_by_id(self, memory_id: str) -> Optional[MemoryEntry]:
        for e in self._entries:
            if e.id == memory_id:
                return e
        return None

    def quarantine(self, memory_id: str, reason: str = "Quarantined by security response") -> bool:
        entry = self.get_by_id(memory_id)
        if entry:
            entry.quarantined = True
            event = CommonEvent(
                source="containment_engine",
                entity=f"memory:{memory_id}",
                event_type="memory_quarantined",
                evidence={"memory_id": memory_id, "reason": reason, "author": entry.agent},
                severity="medium",
                confidence=1.0,
                related_entities=[f"agent:{entry.agent}", f"memory:{memory_id}"]
            )
            self._event_bus.append(event)
            return True
        return False

    def clear(self):
        self._entries.clear()


class MessageBus:
    """Inter-agent message routing bus with provenance tracing and impersonation detection."""

    def __init__(self, event_bus: Optional[List[CommonEvent]] = None):
        self._messages: List[BusMessage] = []
        self._inboxes: Dict[str, List[BusMessage]] = {}
        self._event_bus = event_bus if event_bus is not None else []
        self._provenance_edges: List[Dict[str, Any]] = []

    def send(
        self,
        sender: str,
        recipient: str,
        content: str,
        impersonated_from: Optional[str] = None,
        metadata: Optional[dict] = None
    ) -> tuple[BusMessage, CommonEvent]:
        msg = BusMessage(
            sender=sender,
            recipient=recipient,
            content=content,
            impersonated_from=impersonated_from,
            metadata=metadata or {}
        )
        self._messages.append(msg)
        if recipient not in self._inboxes:
            self._inboxes[recipient] = []
        self._inboxes[recipient].append(msg)

        # Track provenance edge
        apparent_sender = impersonated_from or sender
        self._provenance_edges.append({
            "from": apparent_sender,
            "actual_sender": sender,
            "to": recipient,
            "type": "message",
            "message_id": msg.id,
            "timestamp": msg.timestamp
        })

        if impersonated_from and impersonated_from != sender:
            # Impersonation detected
            event = CommonEvent(
                source="message_bus",
                entity=f"agent:{sender}",
                event_type="impersonation_detected",
                evidence={
                    "actual_sender": sender,
                    "claimed_identity": impersonated_from,
                    "recipient": recipient,
                    "message_id": msg.id,
                    "content_preview": content[:120]
                },
                severity="critical",
                confidence=0.95,
                related_entities=[f"agent:{sender}", f"agent:{recipient}", f"claimed:{impersonated_from}"]
            )
        else:
            event = CommonEvent(
                source=f"agent:{sender}",
                entity=f"agent:{sender}",
                event_type="message_sent",
                evidence={
                    "sender": sender,
                    "recipient": recipient,
                    "message_id": msg.id,
                    "content_preview": content[:120]
                },
                severity="info",
                confidence=1.0,
                related_entities=[f"agent:{sender}", f"agent:{recipient}"]
            )
        self._event_bus.append(event)
        return msg, event

    def receive(self, recipient: str) -> list[BusMessage]:
        inbox = self._inboxes.get(recipient, [])
        messages = list(inbox)
        inbox.clear()
        return messages

    def get_provenance_edges(self) -> list[dict]:
        return list(self._provenance_edges)

    def clear(self):
        self._messages.clear()
        self._inboxes.clear()
        self._provenance_edges.clear()
