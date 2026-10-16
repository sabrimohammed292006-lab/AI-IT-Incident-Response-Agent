"""The Python workflow that runs AFTER the Agents finish.

    triage (Agent) -> investigation (Agents + tools) -> finalize_incident (this file)

finalize_incident() is the only place a ticket gets created. It:
  1. re-validates the report against the tool results (output guardrail rules),
  2. applies the escalation rules in code,
  3. creates the ticket (status pending_human_review when needed, never auto-closed),
  4. returns a ready-to-show message for the UI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, Field

from .guardrails import validate_report
from .safety import evaluate_escalation
from .schemas import InvestigationReport, Severity, TriageResult, max_severity
from .tickets import TicketRequest, TicketStatus, create_incident_ticket

UNSUPPORTED_SOLUTION_STEP = (
    "An IT specialist will review this issue. The automatic analysis could not confirm a safe fix."
)


class IncidentOutcome(BaseModel):
    success: bool
    ticket_id: str | None = None
    ticket_status: TicketStatus | None = None
    duplicate_ticket: bool = False
    severity: Severity
    needs_human_review: bool
    escalation_reasons: list[str] = Field(default_factory=list)
    report_problems: list[str] = Field(default_factory=list)
    steps_for_user: list[str] = Field(default_factory=list)
    message: str


def _outage_id(tool_results: Iterable[dict]) -> str | None:
    for r in tool_results:
        if r.get("tool") == "check_network_status" and r.get("success") and r.get("active_outage_id"):
            return r["active_outage_id"]
    return None


def finalize_incident(
    triage: TriageResult,
    report: InvestigationReport,
    requester_id: str,
    tool_results: list[dict],
    db_path: str | Path | None = None,
) -> IncidentOutcome:
    """Turn the Agents' results into a safe, stored ticket."""
    called = {r["tool"] for r in tool_results if r.get("success") and r.get("tool")}
    check = validate_report(report, called)

    steps = list(report.recommended_steps)
    root_cause = report.root_cause
    reasons: list[str] = []
    if not check.valid:
        # Never show an unsupported or unsafe solution to the user.
        steps = [UNSUPPORTED_SOLUTION_STEP]
        root_cause = None
        reasons.append("Report failed validation: " + " | ".join(check.problems))

    decision = evaluate_escalation(
        category=report.category,
        severity=max_severity(triage.severity, report.severity),
        tool_results=tool_results,
        security_indicators=triage.security_indicators,
    )
    reasons += decision.reasons
    needs_review = decision.needs_human_review or report.needs_human_review or not check.valid

    ticket = create_incident_ticket(
        TicketRequest(
            requester_id=requester_id,
            employee_id=triage.employee_id,
            category=report.category,
            severity=decision.final_severity,
            summary=triage.summary,
            findings=report.findings,
            root_cause=root_cause,
            recommended_steps=steps,
            needs_human_review=needs_review,
            escalation_reasons=reasons,
            linked_outage_id=_outage_id(tool_results),
        ),
        db_path=db_path,
    )

    if not ticket.success:
        return IncidentOutcome(
            success=False, severity=decision.final_severity, needs_human_review=True,
            escalation_reasons=reasons, report_problems=check.problems, steps_for_user=[],
            message=f"Could not create a ticket: {ticket.error.message}",
        )

    if needs_review:
        message = (f"Ticket {ticket.ticket_id} was created and sent to an IT specialist for review "
                   f"(severity: {decision.final_severity}). It will not be closed automatically.")
    else:
        message = f"Ticket {ticket.ticket_id} was created (severity: {decision.final_severity})."
    if ticket.duplicate:
        message = f"This issue is already being handled in ticket {ticket.ticket_id}."

    return IncidentOutcome(
        success=True,
        ticket_id=ticket.ticket_id,
        ticket_status=ticket.status,
        duplicate_ticket=ticket.duplicate,
        severity=decision.final_severity,
        needs_human_review=needs_review,
        escalation_reasons=reasons,
        report_problems=check.problems,
        steps_for_user=steps,
        message=message,
    )
