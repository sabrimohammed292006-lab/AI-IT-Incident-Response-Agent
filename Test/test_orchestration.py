
from models import TriageResult
from orchestration import determine_route


def make_result(
    category,
    severity,
    needs_human_review=False,
):
    return TriageResult(
        category=category,
        severity=severity,
        reasoning=(
            "This is a test result used to validate routing rules."
        ),
        suggested_workers=["account"],
        needs_human_review=needs_human_review,
        confidence=0.9,
    )


def check_route(
    test_name,
    result,
    expected_route,
    expected_workers,
):
    route, workers, message = determine_route(result)

    assert route == expected_route, (
        f"{test_name}: expected route {expected_route}, got {route}"
    )

    assert workers == expected_workers, (
        f"{test_name}: expected workers {expected_workers}, got {workers}"
    )

    print(f"{test_name}: PASS")


def main():
    check_route(
        "Normal account routing",
        make_result("account", "low"),
        "worker_pending",
        ["account"],
    )

    check_route(
        "Security escalation",
        make_result("security", "high", True),
        "human_review",
        [],
    )

    check_route(
        "Unknown incident escalation",
        make_result("unknown", "low"),
        "human_review",
        [],
    )

    check_route(
        "High severity escalation",
        make_result("network", "high"),
        "human_review",
        [],
    )

    check_route(
        "Critical severity escalation",
        make_result("device", "critical"),
        "human_review",
        [],
    )

    check_route(
        "Human review flag",
        make_result("account", "low", True),
        "human_review",
        [],
    )

    print("\nAll orchestration routing tests passed!")


if __name__ == "__main__":
    main()
