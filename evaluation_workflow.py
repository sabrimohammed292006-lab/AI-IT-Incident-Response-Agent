
from models import InvestigationResult, EvaluationResult
from config import MAX_EVALUATION_ITERATIONS


def evaluate_investigation(
    investigation: InvestigationResult,
) -> EvaluationResult:
    """Evaluate investigation quality using deterministic rules."""

    feedback = []
    score = 1.0

    if not investigation.summary.strip():
        feedback.append("The investigation summary is missing.")
        score -= 0.4

    if not investigation.evidence:
        feedback.append("No investigation evidence was provided.")
        score -= 0.4

    if not investigation.recommendation.strip():
        feedback.append("The recommendation is missing.")
        score -= 0.4

    if investigation.requires_human_review:
        feedback.append(
            "The investigation requires human review before further action."
        )

        return EvaluationResult(
            accepted=False,
            score=max(0.0, min(1.0, score)),
            feedback=" ".join(feedback),
            needs_revision=False,
            needs_human_review=True,
        )

    if not feedback:
        feedback.append(
            "The result contains a summary, evidence, and a recommendation."
        )

    accepted = score >= 0.8 and not any(
        "missing" in item.casefold()
        or "no investigation evidence" in item.casefold()
        for item in feedback
    )

    return EvaluationResult(
        accepted=accepted,
        score=max(0.0, min(1.0, score)),
        feedback=" ".join(feedback),
        needs_revision=not accepted,
        needs_human_review=False,
    )


def should_retry(
    evaluation: EvaluationResult,
    attempt_number: int,
) -> bool:
    """Decide whether another evaluation attempt is allowed."""

    if attempt_number >= MAX_EVALUATION_ITERATIONS:
        return False

    if evaluation.needs_human_review:
        return False

    return evaluation.needs_revision
