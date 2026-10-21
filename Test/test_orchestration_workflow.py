
import asyncio

from models import IncidentReport
from orchestration import orchestrate_incident


async def main():
    incident = IncidentReport(
        incident_id="INC-ORCH-001",
        description=(
            "An employee received an unexpected login "
            "notification from an unknown location."
        ),
        affected_service="Employee account",
    )

    result = await orchestrate_incident(incident)

    print("\n--- Orchestration Workflow Test ---")
    print("Incident ID:", result.incident_id)
    print("Category:", result.triage.category)
    print("Severity:", result.triage.severity)
    print("Route:", result.route)
    print("Suggested workers:", result.suggested_workers)
    print("Human review:", result.human_review_required)
    print("Message:", result.message)

    assert result.incident_id == incident.incident_id

    if (
        result.triage.category == "security"
        or result.triage.severity in ("high", "critical")
        or result.triage.needs_human_review
    ):
        assert result.route == "human_review"
        assert result.human_review_required is True
        assert result.suggested_workers == []

    print("\nOrchestration workflow test passed!")


if __name__ == "__main__":
    asyncio.run(main())
