
from models import IncidentReport, TriageResult
from triage_safety import enforce_triage_safety


def main():
    incident = IncidentReport(
        incident_id="INC-SAFETY-001",
        description=(
            "An employee received an unexpected login "
            "notification from an unknown location."
        ),
        affected_service="Employee account",
    )

    result = TriageResult(
        category="account",
        severity="low",
        reasoning=(
            "The initial classification identified an account issue."
        ),
        suggested_workers=["account"],
        needs_human_review=False,
        confidence=0.8,
    )

    safe_result = enforce_triage_safety(
        incident,
        result,
    )

    print("\n--- Safety Test Result ---")
    print("Category:", safe_result.category)
    print("Severity:", safe_result.severity)
    print("Human review:", safe_result.needs_human_review)
    print("Reasoning:", safe_result.reasoning)

    assert safe_result.category == "security"
    assert safe_result.severity == "high"
    assert safe_result.needs_human_review is True

    assert "security" in safe_result.reasoning.casefold()
    assert "human review" in safe_result.reasoning.casefold()
    assert "medium-severity account incident" not in (
        safe_result.reasoning.casefold()
    )

    print("\nAll safety checks passed!")


if __name__ == "__main__":
    main()
