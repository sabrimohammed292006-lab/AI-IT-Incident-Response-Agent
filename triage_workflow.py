
import logging

from agents import Runner, SQLiteSession, trace

from agent_definitions import triage_agent
from config import DATABASE_PATH, TRACING_ENABLED
from logging_config import workflow_logger
from models import IncidentReport, TriageResult
from triage_safety import enforce_triage_safety


def create_incident_session(session_id: str) -> SQLiteSession:
    """Create a persistent conversation session for an incident."""
    return SQLiteSession(
        session_id,
        DATABASE_PATH,
    )


async def run_triage(
    incident: IncidentReport,
    session: SQLiteSession | None = None,
) -> TriageResult:
    """Classify an incident and enforce mandatory safety rules."""

    if session is None:
        session = create_incident_session(incident.incident_id)

    workflow_logger.info(
        "Starting triage for incident %s",
        incident.incident_id,
    )

    try:
        with trace(
            "Incident Triage Workflow",
            disabled=not TRACING_ENABLED,
        ):
            result = await Runner.run(
                triage_agent,
                incident.model_dump_json(),
                session=session,
            )

            triage_result = result.final_output

            if not isinstance(triage_result, TriageResult):
                triage_result = TriageResult.model_validate(
                    triage_result
                )

            safe_result = enforce_triage_safety(
                incident,
                triage_result,
            )

            workflow_logger.info(
                "Triage completed for incident %s | category=%s | severity=%s | human_review=%s",
                incident.incident_id,
                safe_result.category,
                safe_result.severity,
                safe_result.needs_human_review,
            )

            return safe_result

    except Exception:
        workflow_logger.exception(
            "Triage failed for incident %s",
            incident.incident_id,
        )
        raise
