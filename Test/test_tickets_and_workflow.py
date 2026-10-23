import sqlite3

from it_support.check_tools import (
    check_account_status,
    check_device_status,
    check_network_status,
)
from it_support.schemas import Finding, InvestigationReport, TriageResult
from it_support.tickets import (
    TicketRequest,
    close_ticket,
    create_incident_ticket,
    get_ticket,
    list_tickets,
)
from it_support.workflow import UNSUPPORTED_SOLUTION_STEP, finalize_incident


def _req(**overrides):
    base = dict(requester_id="EMP002", employee_id="EMP002", category="account",
                severity="medium", summary="Account locked", needs_human_review=False)
    base.update(overrides)
    return TicketRequest(**base)


# ---------- Tickets ----------

def test_create_and_read_ticket(db_path):
    r = create_incident_ticket(_req(), db_path=db_path)
    assert r.success and r.status == "open"
    assert r.ticket_id.startswith("INC-")
    t = get_ticket(r.ticket_id, db_path=db_path)
    assert t["employee_id"] == "EMP002" and t["status"] == "open"


def test_review_needed_goes_to_pending(db_path):
    r = create_incident_ticket(_req(needs_human_review=True), db_path=db_path)
    assert r.status == "pending_human_review"


def test_duplicate_ticket_not_created_twice(db_path):
    first = create_incident_ticket(_req(), db_path=db_path)
    second = create_incident_ticket(_req(), db_path=db_path)
    assert second.duplicate is True and second.ticket_id == first.ticket_id
    assert len(list_tickets(db_path=db_path)) == 1


def test_cannot_open_ticket_for_someone_else(db_path):
    r = create_incident_ticket(_req(requester_id="EMP001"), db_path=db_path)
    assert r.success is False and r.error.code == "UNAUTHORIZED"


def test_it_staff_can_open_ticket_for_others(db_path):
    assert create_incident_ticket(_req(requester_id="EMP005"), db_path=db_path).success


def test_unknown_requester_rejected(db_path):
    r = create_incident_ticket(_req(requester_id="EMP999", employee_id=None), db_path=db_path)
    assert r.error.code == "UNAUTHORIZED"


def test_invalid_ticket_data(db_path):
    r = create_incident_ticket({"requester_id": "EMP002", "summary": "   "}, db_path=db_path)
    assert r.error.code == "INVALID_INPUT"


def test_sql_injection_is_stored_as_plain_text(db_path):
    evil = "x'); DROP TABLE tickets; --"
    r = create_incident_ticket(_req(summary=evil), db_path=db_path)
    assert get_ticket(r.ticket_id, db_path=db_path)["summary"] == evil
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM tickets").fetchone()[0] == 1


def test_agents_cannot_close_tickets(db_path):
    r = create_incident_ticket(_req(), db_path=db_path)
    assert close_ticket(r.ticket_id, "EMP005", actor="agent", db_path=db_path).error.code == "UNAUTHORIZED"
    assert close_ticket(r.ticket_id, "EMP001", actor="human", db_path=db_path).error.code == "UNAUTHORIZED"
    assert close_ticket(r.ticket_id, "EMP005", actor="human", db_path=db_path).status == "closed"


def test_database_error_is_reported(tmp_path):
    folder_not_file = tmp_path / "a_folder.db"
    folder_not_file.mkdir()
    r = create_incident_ticket(_req(), db_path=folder_not_file)
    assert r.success is False and r.error.code == "DATA_UNAVAILABLE"


# ---------- Workflow ----------

def _triage(**overrides):
    base = dict(category="account", severity="medium", summary="Cannot log in, account locked",
                employee_id="EMP002", device_id=None, site=None, security_indicators=[])
    base.update(overrides)
    return TriageResult(**base)


def test_normal_incident(db_path):
    tool_results = [check_account_status("EMP002")]
    report = InvestigationReport(
        category="account", severity="medium",
        findings=[Finding(tool_used="check_account_status", observation="Locked, 5 failed logins.")],
        root_cause="Too many failed logins.",
        recommended_steps=["IT staff unlocks the account after verifying identity."],
        needs_human_review=False)
    out = finalize_incident(_triage(), report, "EMP002", tool_results, db_path=db_path)
    assert out.success and out.ticket_status == "open"
    assert out.steps_for_user == report.recommended_steps


def test_security_incident_goes_to_human(db_path):
    tool_results = [check_device_status("DEV-1003")]
    report = InvestigationReport(
        category="device", severity="medium",
        findings=[Finding(tool_used="check_device_status", observation="2 security alerts.")],
        root_cause=None, recommended_steps=["Disconnect the device from the network."],
        needs_human_review=False)
    out = finalize_incident(_triage(category="device", employee_id="EMP005", device_id="DEV-1003"),
                            report, "EMP005", tool_results, db_path=db_path)
    assert out.severity == "critical"
    assert out.needs_human_review is True
    assert out.ticket_status == "pending_human_review"


def test_unsupported_solution_is_hidden_from_user(db_path):
    report = InvestigationReport(
        category="account", severity="low", findings=[], root_cause="Probably a virus",
        recommended_steps=["Reinstall Windows"], needs_human_review=False)
    out = finalize_incident(_triage(), report, "EMP002", [], db_path=db_path)
    assert out.steps_for_user == [UNSUPPORTED_SOLUTION_STEP]
    assert out.needs_human_review is True
    assert get_ticket(out.ticket_id, db_path=db_path)["root_cause"] is None


def test_outage_tickets_are_linked_not_duplicated(db_path):
    tool_results = [check_network_status("GIZA-OFFICE")]
    report = InvestigationReport(
        category="network", severity="high",
        findings=[Finding(tool_used="check_network_status", observation="GIZA-OFFICE is down.")],
        root_cause="Site outage OUT-2026-0412.",
        recommended_steps=["Inform users that the network team is working on the outage."],
        needs_human_review=True)
    t1 = finalize_incident(_triage(category="network", employee_id="EMP001", site="GIZA-OFFICE"),
                           report, "EMP001", tool_results, db_path=db_path)
    t2 = finalize_incident(_triage(category="network", employee_id="EMP006", site="GIZA-OFFICE"),
                           report, "EMP006", tool_results, db_path=db_path)
    assert t2.duplicate_ticket and t2.ticket_id == t1.ticket_id
