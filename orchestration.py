
from dataclasses import dataclass

from agents import SQLiteSession

from config import DATABASE_PATH
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


def determine_route(
    triage: TriageResult,
) -> tuple[str, list[str], str]:
    """Choose the next workflow route from the triage result."""

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
            "The account worker must be connected before investigation.",
        )

    if triage.category in ("vpn", "network"):
        return (
            "worker_pending",
            ["network"],
            "The network worker must be connected before investigation.",
        )

    if triage.category == "device":
        return (
            "worker_pending",
            ["device"],
            "The device worker must be connected before investigation.",
        )

    if triage.category == "unknown":
        return (
            "human_review",
            [],
            "The incident category is unknown and requires human review.",
        )

    return (
        "human_review",
        [],
        "No safe automated route is available for this incident.",
    )


async def orchestrate_incident(
    incident: IncidentReport,
    session: SQLiteSession | None = None,
) -> OrchestrationResult:
    """Run triage and determine the next safe workflow step."""

    if session is None:
        session = SQLiteSession(
            incident.incident_id,
            DATABASE_PATH,
        )

    triage_result = await run_triage(
        incident,
        session=session,
    )

    route, workers, message = determine_route(
        triage_result,
    )

    return OrchestrationResult(
        incident_id=incident.incident_id,
        triage=triage_result,
        route=route,
        suggested_workers=workers,
        human_review_required=(route == "human_review"),
        message=message,
    )
