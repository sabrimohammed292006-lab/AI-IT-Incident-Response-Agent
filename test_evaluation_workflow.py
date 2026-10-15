
from evaluation_workflow import (
    evaluate_investigation,
    should_retry,
)
from models import InvestigationResult


def main():
    good_result = InvestigationResult(
        summary="The employee reported a VPN connection failure.",
        evidence=[
            "The employee reported that the VPN connection failed."
        ],
        recommendation=(
            "Request the exact VPN error message before further diagnosis."
        ),
        requires_human_review=False,
    )

    evaluation = evaluate_investigation(good_result)

    assert evaluation.accepted is True
    assert evaluation.needs_revision is False
    assert evaluation.needs_human_review is False
    assert should_retry(evaluation, 1) is False

    print("Valid investigation evaluation: PASS")

    human_review_result = InvestigationResult(
        summary="The report indicates possible unauthorized account access.",
        evidence=[
            "The report mentions an unexpected login notification."
        ],
        recommendation=(
            "Escalate the incident for security review."
        ),
        requires_human_review=True,
    )

    evaluation = evaluate_investigation(human_review_result)

    assert evaluation.accepted is False
    assert evaluation.needs_human_review is True
    assert should_retry(evaluation, 1) is False

    print("Human review handling: PASS")

    incomplete_result = InvestigationResult(
        summary="The VPN connection failed.",
        evidence=[],
        recommendation="Collect diagnostic information.",
        requires_human_review=False,
    )

    evaluation = evaluate_investigation(incomplete_result)

    assert evaluation.accepted is False
    assert evaluation.needs_revision is True
    assert should_retry(evaluation, 1) is True
    assert should_retry(evaluation, 3) is False

    print("Retry limit handling: PASS")
    print("\nAll evaluation workflow tests passed!")


if __name__ == "__main__":
    main()
