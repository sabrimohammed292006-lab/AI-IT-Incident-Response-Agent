
import json
from dataclasses import dataclass

from agents import Runner, SQLiteSession, trace

from agent_definitions import (
    investigation_agent,
    investigation_report_agent,
)
from config import DATABASE_PATH, TRACING_ENABLED
from it_support.context import IncidentContext
from it_support.schemas import InvestigationReport
from investigation_workflow import report_to_investigation_result
from logging_config import workflow_logger
from models import IncidentReport, TriageResult
from triage_workflow import run_triage


@dataclass
class OrchestrationResult:
    incident_id: str
    triage: TriageResult
    route: str
    suggested_workers: list[str]
    human_review_required: bool
    message: str
    investigation: object | None = None


def determine_route(
    triage: TriageResult,
) -> tuple[str, list[str], str]:

    if (
        triage.needs_human_review
        or triage.severity in ("high", "critical")
        or triage.category == "security"
    ):
        return (
            "human_review",
            [],
            "Human review is required before automated investigation.",
        )

    if triage.category == "account":
        return (
            "worker_pending",
            ["account"],
            "Account investigation is ready to run.",
        )

    if triage.category in ("vpn", "network"):
        return (
            "worker_pending",
            ["network"],
            "Network investigation is ready to run.",
        )

    if triage.category == "device":
        return (
            "worker_pending",
            ["device"],
            "Device investigation is ready to run.",
        )

    return (
        "human_review",
        [],
        "The incident category is unknown and requires human review.",
    )


async def orchestrate_incident(
    incident: IncidentReport,
    session: SQLiteSession | None = None,
) -> OrchestrationResult:

    if session is None:
        session = SQLiteSession(
            incident.incident_id,
            DATABASE_PATH,
        )

    # Stage 1: classify the incident.
    triage_result = await run_triage(
        incident,
        session=session,
    )

    route, workers, message = determine_route(triage_result)

    if route == "human_review":
        return OrchestrationResult(
            incident_id=incident.incident_id,
            triage=triage_result,
            route=route,
            suggested_workers=workers,
            human_review_required=True,
            message=message,
        )

    # Do not assume the affected employee is the authenticated requester.
    context = IncidentContext(requester_id=None)

    try:
        with trace(
            "Incident Investigation Workflow",
            disabled=not TRACING_ENABLED,
        ):
            # Stage 2: run tools and collect investigation notes.
            investigation_run = await Runner.run(
                investigation_agent,
                (
                    "Investigate this IT incident using the available tools.\n"
                    f"Incident ID: {incident.incident_id}\n"
                    f"Description: {incident.description}\n"
                    f"Affected service: {incident.affected_service}\n"
                    f"Triage category: {triage_result.category}\n"
                    f"Triage severity: {triage_result.severity}\n"
                    "Use tool results as the only source of technical evidence."
                ),
                context=context,
                session=session,
            )

            recorded_tools = list(context.tool_log)
            successful_tools = context.called_tools

            print("\n========== INVESTIGATION DEBUG ==========")
            print("TOOL LOG:", recorded_tools)
            print("CALLED TOOLS:", successful_tools)
            print("INVESTIGATION NOTES:", investigation_run.final_output)
            print("=========================================\n")

            # Stage 3: generate a report only if a tool succeeded.
            if not successful_tools:
                report = InvestigationReport(
                    category=triage_result.category,
                    severity=triage_result.severity,
                    findings=[],
                    root_cause=None,
                    recommended_steps=[],
                    needs_human_review=True,
                )
            else:
                evidence_json = json.dumps(
                    recorded_tools,
                    ensure_ascii=False,
                    default=str,
                )

                report_prompt = (
                    "Create an InvestigationReport for this incident.\n\n"
                    f"Incident ID: {incident.incident_id}\n"
                    f"Description: {incident.description}\n"
                    f"Affected service: {incident.affected_service}\n"
                    f"Triage category: {triage_result.category}\n"
                    f"Triage severity: {triage_result.severity}\n\n"
                    "Investigation notes:\n"
                    f"{investigation_run.final_output}\n\n"
                    "Recorded tool results (JSON):\n"
                    f"{evidence_json}\n\n"
                    "Security and evidence rules:\n"
                    "- Use only successful tool results as technical evidence.\n"
                    "- Every finding's tool_used must match a successful tool name.\n"
                    "- Never treat failed or unauthorized checks as findings.\n"
                    "- Do not invent technical facts or a root cause.\n"
                    "- If evidence is insufficient, set root_cause to null,\n"
                    "  avoid unsupported findings, and require human review.\n"
                    "- Preserve the incident category and severity."
                )

                report_run = await Runner.run(
                    investigation_report_agent,
                    report_prompt,
                    context=context,
                )

                report = report_run.final_output

        if not isinstance(report, InvestigationReport):
            report = InvestigationReport.model_validate(report)

        investigation = report_to_investigation_result(
            report,
            recorded_tools,
        )

        # Enforce human review using the actual recorded tool results.
        successful_records = [
            result
            for result in recorded_tools
            if result.get("success") is True
        ]

        failed_records = [
            result
            for result in recorded_tools
            if result.get("success") is not True
        ]

        has_verified_root_cause = bool(
            getattr(investigation, "root_cause", None)
        )

        needs_review = (
            investigation.requires_human_review
            or not investigation.evidence
            or not successful_records
            or report.needs_human_review
            or bool(failed_records)
            or not has_verified_root_cause
            or triage_result.severity in ("high", "critical")
            or triage_result.category == "security"
        )

        return OrchestrationResult(
            incident_id=incident.incident_id,
            triage=triage_result,
            route=(
                "human_review"
                if needs_review
                else "investigation_complete"
            ),
            suggested_workers=workers,
            human_review_required=needs_review,
            message=(
                "Investigation completed; human review is required."
                if needs_review
                else "Investigation completed using recorded tool results."
            ),
            investigation=investigation,
        )

    except Exception:
        workflow_logger.exception(
            "Investigation failed for incident %s",
            incident.incident_id,
        )

        return OrchestrationResult(
            incident_id=incident.incident_id,
            triage=triage_result,
            route="human_review",
            suggested_workers=workers,
            human_review_required=True,
            message=(
                "Investigation could not be safely completed. "
                "Human review is required."
            ),
        )
