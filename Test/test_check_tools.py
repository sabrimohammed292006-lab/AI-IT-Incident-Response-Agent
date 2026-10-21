"""Tests for the four check tools. Run with:  python -m pytest -v"""

import asyncio
import json

import pytest
from agents import AgentOutputSchema
from agents.tool_context import ToolContext

from it_support import data_store
from it_support.check_tools import (
    CHECK_TOOLS,
    check_account_status,
    check_account_status_tool,
    check_device_status,
    check_network_status,
    check_vpn_status,
)
from it_support.schemas import InvestigationReport, TriageResult


# ---------- Account ----------

def test_account_locked():
    r = check_account_status("EMP002")
    assert r["success"] is True
    assert r["account_status"] == "locked"
    assert r["failed_login_attempts"] == 5


def test_account_input_is_normalized():
    assert check_account_status("  emp001 ")["employee_id"] == "EMP001"


def test_account_not_found_does_not_invent_status():
    r = check_account_status("EMP999")
    assert r["success"] is False
    assert r["error"]["code"] == "NOT_FOUND"
    assert r["account_status"] is None


@pytest.mark.parametrize("bad", ["", "   ", None, 123, "EMP1", "'; DROP TABLE users; --"])
def test_account_invalid_input(bad):
    r = check_account_status(bad)
    assert r["success"] is False
    assert r["error"]["code"] == "INVALID_INPUT"


# ---------- VPN ----------

def test_vpn_certificate_expired_and_old_client():
    r = check_vpn_status("EMP005")
    assert r["vpn_status"] == "error"
    assert r["certificate_valid"] is False
    assert r["client_up_to_date"] is False


def test_vpn_missing_record_is_reported_not_guessed():
    # EMP003 has an account but no VPN record.
    r = check_vpn_status("EMP003")
    assert r["success"] is False
    assert r["error"]["code"] == "NOT_FOUND"
    assert r["vpn_status"] is None


# ---------- Device ----------

def test_device_low_disk():
    r = check_device_status("dev-1002")
    assert r["success"] is True
    assert r["disk_free_percent"] == 4


def test_device_security_alerts():
    r = check_device_status("DEV-1003")
    assert r["antivirus_status"] == "disabled"
    assert len(r["security_alerts"]) == 2


def test_device_invalid_id():
    assert check_device_status("laptop")["error"]["code"] == "INVALID_INPUT"


# ---------- Network ----------

def test_network_down_with_outage():
    r = check_network_status("giza office")
    assert r["site"] == "GIZA-OFFICE"
    assert r["network_status"] == "down"
    assert r["active_outage_id"] == "OUT-2026-0412"


def test_network_monitoring_offline_is_a_tool_error():
    r = check_network_status("ASWAN-BRANCH")
    assert r["success"] is False
    assert r["error"]["code"] == "DATA_UNAVAILABLE"


def test_missing_data_file_returns_error_not_crash(monkeypatch):
    monkeypatch.setattr(data_store, "SYSTEMS_FILE", "does_not_exist.json")
    monkeypatch.setattr("it_support.check_tools.get_section",
                        lambda s: data_store.load_json("does_not_exist.json"))
    r = check_account_status("EMP001")
    assert r["success"] is False
    assert r["error"]["code"] == "DATA_UNAVAILABLE"


# ---------- Agents SDK integration ----------

def test_tools_are_valid_function_tools():
    names = {t.name for t in CHECK_TOOLS}
    assert names == {"check_account_status", "check_vpn_status",
                     "check_device_status", "check_network_status"}
    for t in CHECK_TOOLS:
        assert t.description, f"{t.name} needs a description for the Agent"
        assert len(t.params_json_schema["properties"]) == 1


def test_tool_runs_through_the_sdk():
    """Call the tool the same way an Agent would (JSON arguments)."""
    args = json.dumps({"employee_id": "EMP002"})
    ctx = ToolContext(context=None, tool_name=check_account_status_tool.name,
                      tool_call_id="test-1", tool_arguments=args)
    output = asyncio.run(check_account_status_tool.on_invoke_tool(ctx, args))
    assert "locked" in str(output)


@pytest.mark.parametrize("model", [TriageResult, InvestigationReport])
def test_shared_models_work_as_agent_output_type(model):
    # Fails if the teammate could not use this model as Agent(output_type=...)
    schema = AgentOutputSchema(model).json_schema()
    assert schema["type"] == "object"
