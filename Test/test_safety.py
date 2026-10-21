import pytest

from it_support.check_tools import (
    check_account_status,
    check_device_status,
    check_network_status,
    check_vpn_status,
)
from it_support.safety import check_action_safety, evaluate_escalation, is_it_staff


# ---------- Escalation ----------

def test_simple_issue_no_escalation():
    d = evaluate_escalation("device", "low", [check_device_status("DEV-1002")])
    assert d.needs_human_review is False
    assert d.allow_auto_close is True


def test_device_security_alerts_are_critical():
    d = evaluate_escalation("device", "low", [check_device_status("DEV-1003")])
    assert d.final_severity == "critical"
    assert d.needs_human_review is True
    assert d.allow_auto_close is False


def test_security_category_always_escalates():
    d = evaluate_escalation("security", "low", [])
    assert d.final_severity == "critical" and d.needs_human_review


def test_security_indicators_escalate():
    d = evaluate_escalation("account", "medium", [], security_indicators=["phishing email clicked"])
    assert d.final_severity == "critical"


def test_disabled_account_needs_human():
    d = evaluate_escalation("account", "low", [check_account_status("EMP003")])
    assert d.needs_human_review and d.final_severity == "high"


def test_network_down_is_high():
    d = evaluate_escalation("network", "medium", [check_network_status("GIZA-OFFICE")])
    assert d.final_severity == "high"
    assert "OUT-2026-0412" in d.reasons[0]


def test_tool_failure_cannot_be_auto_resolved():
    d = evaluate_escalation("network", "low", [check_network_status("ASWAN-BRANCH")])
    assert d.needs_human_review is True


def test_brute_force_detection():
    fake = {"tool": "check_account_status", "success": True, "employee_id": "EMP001",
            "account_status": "locked", "failed_login_attempts": 25}
    assert evaluate_escalation("account", "low", [fake]).final_severity == "critical"


def test_severity_never_goes_down():
    d = evaluate_escalation("vpn", "critical", [check_vpn_status("EMP001")])
    assert d.final_severity == "critical" and d.needs_human_review


# ---------- Dangerous actions ----------

@pytest.mark.parametrize("step", [
    "Disable the antivirus and try again",
    "Turn off Windows Firewall",
    "Bypass MFA for this user",
    "Delete the audit logs",
    "Format the C: drive",
    "Run rm -rf / on the server",
    "Grant the user admin rights",
    "Send your password to the IT team by email",
    "Open regedit and delete the key",
    "Ignore the certificate error",
    "Pay the ransom",
    "اقفل الانتي فايرس",
])
def test_dangerous_steps_are_blocked(step):
    assert check_action_safety(step).allowed is False


@pytest.mark.parametrize("step", [
    "Restart the VPN client and try again.",
    "Use the self-service portal to set a new password.",
    "Empty the Recycle Bin.",
    "Install the latest approved VPN client.",
])
def test_safe_steps_are_allowed(step):
    assert check_action_safety(step).allowed is True


def test_it_staff():
    assert is_it_staff("EMP005") is True
    assert is_it_staff("EMP001") is False
    assert is_it_staff("not-an-id") is False
