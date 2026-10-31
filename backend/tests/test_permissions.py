"""Phase 1 tests: Agent tool call permission checks and forbidden call detection."""
import pytest
from agent_network.permissions import DEFAULT_CONFIG
from agent_network.agents import HelpdeskAgent, LibraryAgent, FinanceAgent, StudentSupportAgent
from agent_network.fixture_data import STUDENT_DB


def test_helpdesk_forbidden_call_is_flagged():
    agent = HelpdeskAgent()
    # Helpdesk is allowed: read_tickets, reply_ticket, post_shared_memory, read_shared_memory
    # Forbidden from: get_fee_record, export_records, etc.
    result = agent.execute_tool("get_fee_record", student_id="STU-2026-001")
    assert result.allowed is False
    assert result.success is False
    assert "Permission denied" in result.error
    assert result.event is not None
    assert result.event.event_type == "permission_denied"
    assert result.event.severity == "high"


def test_helpdesk_allowed_call_passes():
    agent = HelpdeskAgent()
    ticket = agent.add_ticket("TCK-001", "student@campus.edu", "Password Reset", "Please reset my portal pass")
    result = agent.execute_tool("read_tickets")
    assert result.allowed is True
    assert result.success is True
    assert len(result.data) == 1
    assert result.data[0]["ticket_id"] == "TCK-001"


def test_library_forbidden_student_data_call():
    agent = LibraryAgent()
    # Library only allowed: catalogue_search
    # Forbidden from student records
    result = agent.execute_tool("get_fee_record", student_id="STU-2026-001")
    assert result.allowed is False
    assert result.event.event_type == "permission_denied"


def test_library_allowed_catalogue_search():
    agent = LibraryAgent()
    result = agent.execute_tool("catalogue_search", query="Algorithms")
    assert result.allowed is True
    assert result.success is True
    assert any("Algorithms" in b["title"] for b in result.data)


def test_finance_allowed_fee_record_forbidden_export():
    agent = FinanceAgent()
    # Allowed to check fee record
    fee_res = agent.execute_tool("get_fee_record", student_id="STU-2026-001")
    assert fee_res.allowed is True
    assert fee_res.success is True
    assert fee_res.data["student_id"] == "STU-2026-001"

    # Forbidden from exporting all records
    exp_res = agent.execute_tool("export_all_records")
    assert exp_res.allowed is False
    assert exp_res.event.event_type == "permission_denied"


def test_student_support_allowed_own_forbidden_bulk():
    agent = StudentSupportAgent()
    # Allowed own student lookup
    own_res = agent.execute_tool("lookup_own_student", student_id="STU-2026-001")
    assert own_res.allowed is True
    assert own_res.success is True

    # Forbidden from bulk lookup
    bulk_res = agent.execute_tool("bulk_lookup")
    assert bulk_res.allowed is False
    assert bulk_res.event.event_type == "permission_denied"
