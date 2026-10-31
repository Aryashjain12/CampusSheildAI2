from datetime import datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from core.schemas import SecurityEvent, EventCategory, Severity


def test_network_event_creation():
    event = SecurityEvent(
        event_type="port_scan",
        category=EventCategory.NETWORK,
        source="192.168.1.10",
        severity=Severity.HIGH,
    )

    assert event.category == EventCategory.NETWORK
    assert event.severity == Severity.HIGH


def test_agent_event_creation():
    event = SecurityEvent(
        event_type="unauthorized_tool_call",
        category=EventCategory.AGENT,
        source="finance-agent",
        target="database-tool",
    )

    assert event.category == EventCategory.AGENT


def test_event_id_is_valid_uuid():
    event = SecurityEvent(
        event_type="port_scan",
        category="network",
        source="test-host",
    )

    assert isinstance(event.event_id, UUID)


def test_missing_source_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_type="port_scan",
            category="network",
        )


def test_invalid_category_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_type="unknown",
            category="invalid",
            source="test-host",
        )


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_type="port_scan",
            category="network",
            source="test-host",
            timestamp=datetime(2026, 10, 31, 12, 0),
        )
