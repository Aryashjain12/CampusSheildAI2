"""Network correlation detection layer (Section 7 Layer 4).

Correlates prior network alerts (e.g. Wazuh port-scan, Suricata brute-force)
with subsequent multi-agent activity involving the same entity/IP.
"""
from __future__ import annotations
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from agent_network.models import CommonEvent


class NetworkCorrelator:
    """Correlates network alerts with subsequent agent activity from the same IP/host."""

    def __init__(self, event_bus: Optional[List[CommonEvent]] = None):
        self._network_alerts: Dict[str, List[Dict[str, Any]]] = {}
        self._event_bus = event_bus if event_bus is not None else []
        self._correlations: List[Dict[str, Any]] = []

    def record_network_alert(
        self,
        source_id: str,
        alert_type: str,
        destination_id: str,
        severity: str = "high",
        details: dict | None = None
    ) -> CommonEvent:
        clean_source = source_id.replace("ip:", "")
        alert_entry = {
            "source_id": clean_source,
            "alert_type": alert_type,
            "destination_id": destination_id,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {}
        }
        if clean_source not in self._network_alerts:
            self._network_alerts[clean_source] = []
        self._network_alerts[clean_source].append(alert_entry)

        event = CommonEvent(
            source=f"network_detector:{alert_type}",
            entity=f"ip:{clean_source}",
            event_type="network_alert_recorded",
            evidence=alert_entry,
            severity=severity if severity in ("low", "medium", "high", "critical") else "high",
            confidence=0.90,
            related_entities=[f"ip:{clean_source}", f"host:{destination_id}"]
        )
        if not any(e.id == event.id for e in self._event_bus):
            self._event_bus.append(event)
        return event

    def check_correlation(
        self,
        agent_name: str,
        source_id: str,
        activity_type: str = "ticket_submission",
        activity_details: dict | None = None
    ) -> Optional[CommonEvent]:
        clean_source = source_id.replace("ip:", "")
        prior_alerts = self._network_alerts.get(clean_source, [])

        if not prior_alerts:
            # Standalone agent activity, no prior network alert to correlate
            return None

        # Prior suspicious network activity exists for this source!
        alert_types = [a["alert_type"] for a in prior_alerts]
        correlation_evidence = {
            "agent": agent_name,
            "source_id": clean_source,
            "activity_type": activity_type,
            "activity_details": activity_details or {},
            "prior_network_alerts_count": len(prior_alerts),
            "prior_alert_types": alert_types,
            "explanation": f"Network alert ({', '.join(alert_types)}) correlated with agent '{agent_name}' incident from {clean_source}."
        }

        event = CommonEvent(
            source="network_correlation_engine",
            entity=f"ip:{clean_source}",
            event_type="network_correlation_detected",
            evidence=correlation_evidence,
            severity="critical",
            confidence=0.96,
            related_entities=[f"ip:{clean_source}", f"agent:{agent_name}"]
        )
        self._correlations.append(correlation_evidence)
        if not any(e.id == event.id for e in self._event_bus):
            self._event_bus.append(event)
        return event

    def get_correlations(self) -> List[Dict[str, Any]]:
        return list(self._correlations)

    def clear(self):
        self._network_alerts.clear()
        self._correlations.clear()
