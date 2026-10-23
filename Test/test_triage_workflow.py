
import asyncio

from models import IncidentReport
from triage_workflow import run_triage


async def main():
    incident = IncidentReport(
        incident_id="INC-TEST-001",
        description=(
            "An employee received an unexpected login "
            "notification from an unknown location."
        ),
        affected_service="Employee account",
    )

    result = await run_triage(incident)

    print("\n--- Triage Test Result ---")
    print("Incident ID:", incident.incident_id)
    print("Category:", result.category)
    print("Severity:", result.severity)
    print("Human review:", result.needs_human_review)
    print("Confidence:", result.confidence)
    print("Reasoning:", result.reasoning)
    print("Suggested workers:", result.suggested_workers)


if __name__ == "__main__":
    asyncio.run(main())
