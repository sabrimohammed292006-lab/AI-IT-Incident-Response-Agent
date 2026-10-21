from investigation_workflow import (
    report_to_investigation_result,
    tool_log_to_evidence,
)
from it_support.schemas import Finding, InvestigationReport


def make_report(**overrides):
    data = {
        "category": "account",
        "severity": "low",
        "findings": [
            Finding(
                tool_used="check_account_status",
                observation="Invented observation that must not become evidence.",
            )
        ],
        "root_cause": "The account is locked after several failed sign-in attempts.",
        "recommended_steps": [
            "Ask the employee to wait for IT to unlock the account."
        ],
        "needs_human_review": False,
    }
    data.update(overrides)
    return InvestigationReport.model_validate(data)


def check(test_name, condition, detail=""):
    assert condition, f"{test_name} FAILED {detail}"
    print(f"{test_name}: PASS")


def test_successful_tool_results():
    log = [
        {
            "success": True,
            "tool": "check_account_status",
            "source": "mock_data",
            "checked_at": "2026-10-17T00:00:00+00:00",
            "error": None,
            "employee_id": "EMP002",
            "account_status": "locked",
            "failed_login_attempts": 5,
            "mfa_enabled": True,
        }
    ]
    evidence = tool_log_to_evidence(log)
    check(
        "Successful tool evidence includes tool name and facts",
        len(evidence) == 1
        and evidence[0].startswith("check_account_status:")
        and "account_status=locked" in evidence[0]
        and "employee_id=EMP002" in evidence[0]
        and " failed:" not in evidence[0],
        evidence,
    )

    result = report_to_investigation_result(make_report(), log)
    check(
        "Successful mapping uses root cause as summary",
        "locked" in result.summary,
    )
    check(
        "Successful mapping keeps safe recommendation",
        "unlock" in result.recommendation.casefold(),
    )
    check(
        "Successful mapping does not force human review",
        result.requires_human_review is False,
    )
    check(
        "Successful mapping evidence matches the tool log",
        result.evidence == evidence,
    )


def test_failed_tools_are_marked():
    log = [
        {
            "success": False,
            "tool": "check_vpn_status",
            "source": "mock_data",
            "error": {
                "code": "NOT_FOUND",
                "message": "No VPN record found for EMP999.",
            },
            "employee_id": "EMP999",
        },
        {
            "success": False,
            "tool": "check_account_status",
            "error": {
                "code": "UNAUTHORIZED",
                "message": "Requester is not identified.",
            },
        },
    ]
    evidence = tool_log_to_evidence(log)
    check("Failed tools produce two evidence rows", len(evidence) == 2)
    check(
        "Failed VPN attempt is marked with error code",
        evidence[0].startswith("check_vpn_status failed: NOT_FOUND:"),
        evidence[0],
    )
    check(
        "Unauthorized attempt is marked as a failure",
        evidence[1].startswith("check_account_status failed: UNAUTHORIZED:"),
        evidence[1],
    )


def test_empty_log():
    evidence = tool_log_to_evidence([])
    check("Empty log yields no evidence", evidence == [])

    result = report_to_investigation_result(make_report(), [])
    check("Empty log mapping keeps evidence empty", result.evidence == [])
    check(
        "Empty log mapping still produces a valid summary",
        len(result.summary) >= 10,
    )


def test_findings_are_not_evidence():
    invented = "Invented observation that must not become evidence."
    result = report_to_investigation_result(
        make_report(),
        [
            {
                "success": True,
                "tool": "check_account_status",
                "account_status": "locked",
                "employee_id": "EMP002",
            }
        ],
    )
    check(
        "Model findings are not copied into evidence",
        invented not in " ".join(result.evidence),
        result.evidence,
    )


def test_unsafe_recommendations_are_dropped():
    report = make_report(
        recommended_steps=[
            "Guide the employee to the self-service password portal.",
            "Disable antivirus and turn off the firewall.",
        ]
    )
    result = report_to_investigation_result(report, [])
    text = result.recommendation.casefold()
    check(
        "Unsafe recommendation is not passed through",
        "disable antivirus" not in text
        and "firewall" not in text,
        result.recommendation,
    )
    check(
        "Safe recommendation is kept when mixed with an unsafe step",
        "self-service password portal" in text,
        result.recommendation,
    )
    check(
        "Unsafe recommendation forces human review",
        result.requires_human_review is True,
    )

    unsafe_only = report_to_investigation_result(
        make_report(
            recommended_steps=["Disable antivirus on the laptop."],
            needs_human_review=False,
        ),
        [],
    )
    check(
        "Unsafe-only recommendation uses the safe fallback text",
        "no safe recommendation" in unsafe_only.recommendation.casefold(),
        unsafe_only.recommendation,
    )
    check(
        "Unsafe-only recommendation does not repeat the blocked action",
        "disable antivirus" not in unsafe_only.recommendation.casefold(),
        unsafe_only.recommendation,
    )


def test_evidence_cap():
    log = [
        {
            "success": True,
            "tool": "check_network_status",
            "site": f"SITE-{index:02d}",
            "network_status": "up",
        }
        for index in range(25)
    ]
    evidence = tool_log_to_evidence(log)
    check("Evidence is capped at 20 entries", len(evidence) == 20)

    result = report_to_investigation_result(make_report(), log)
    check(
        "Mapped evidence is also capped at 20 entries",
        len(result.evidence) == 20,
    )
    check(
        "Capped evidence keeps the earliest tool results",
        "SITE-00" in result.evidence[0] and "SITE-24" not in " ".join(result.evidence),
        result.evidence[0],
    )


def test_short_root_cause_uses_fallback():
    result = report_to_investigation_result(
        make_report(root_cause="locked"),
        [],
    )
    check(
        "Short root cause is not used as the summary",
        result.summary != "locked" and len(result.summary) >= 10,
        result.summary,
    )


def main():
    test_successful_tool_results()
    test_failed_tools_are_marked()
    test_empty_log()
    test_findings_are_not_evidence()
    test_unsafe_recommendations_are_dropped()
    test_evidence_cap()
    test_short_root_cause_uses_fallback()
    print("\nAll investigation workflow tests passed!")


if __name__ == "__main__":
    main()
