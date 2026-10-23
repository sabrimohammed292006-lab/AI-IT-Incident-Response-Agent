
from models import IncidentReport, TriageResult


def enforce_triage_safety(
    incident: IncidentReport,
    result: TriageResult,
) -> TriageResult:
    """Apply mandatory safety rules after model triage."""

    description = incident.description.casefold()

    security_indicators = (
        "unexpected login",
        "unknown location",
        "unauthorized access",
        "account compromised",
        "suspicious login",
        "stolen credentials",
        "data breach",
        "ransomware",
        "malware",
    )

    matched_indicators = [
        indicator
        for indicator in security_indicators
        if indicator in description
    ]

    security_suspected = (
        result.category == "security"
        or bool(matched_indicators)
    )

    if security_suspected:
        result.category = "security"
        result.needs_human_review = True

        if result.severity not in ("high", "critical"):
            result.severity = "high"

        if matched_indicators:
            indicators_text = ", ".join(matched_indicators)

            result.reasoning = (
                f"The incident description contains security indicators: "
                f"{indicators_text}. The incident is classified as "
                f"security-related and requires human review. "
                f"The available description alone does not confirm "
                f"a successful security compromise."
            )
        else:
            result.reasoning = (
                "The model classified this incident as security-related. "
                "Human review is required. The available information "
                "does not independently confirm a successful compromise."
            )

        if result.severity == "high":
            result.reasoning += (
                " The severity is set to high as a conservative "
                "safety measure."
            )

    if result.severity == "critical":
        result.needs_human_review = True

        if "human review" not in result.reasoning.casefold():
            result.reasoning = (
                result.reasoning.rstrip()
                + " Human review is required because the severity is critical."
            )

    return result
