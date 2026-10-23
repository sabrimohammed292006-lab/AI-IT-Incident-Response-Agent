
from models import InvestigationResult, EvaluationResult


def main():
    investigation = InvestigationResult(
        summary=(
            "The employee cannot access the company VPN."
        ),
        evidence=[
            "The employee reported a VPN connection failure."
        ],
        recommendation=(
            "Collect the VPN error message and check the connection status."
        ),
        requires_human_review=False,
    )

    evaluation = EvaluationResult(
        accepted=True,
        score=0.9,
        feedback=(
            "The result includes a finding, evidence, and a clear next step."
        ),
        needs_revision=False,
        needs_human_review=False,
    )

    print("Investigation summary:", investigation.summary)
    print("Evidence count:", len(investigation.evidence))
    print("Evaluation accepted:", evaluation.accepted)
    print("Evaluation score:", evaluation.score)
    print("Needs revision:", evaluation.needs_revision)

    assert evaluation.accepted is True
    assert evaluation.needs_revision is False
    assert 0.0 <= evaluation.score <= 1.0

    print("\nAll evaluation model tests passed!")


if __name__ == "__main__":
    main()
