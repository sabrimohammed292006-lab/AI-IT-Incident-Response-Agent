
"""Map IT support tool logs and reports onto investigation models."""

from __future__ import annotations

from typing import Any

from it_support.safety import check_action_safety
from it_support.schemas import InvestigationReport
from models import InvestigationResult

MAX_EVIDENCE_ITEMS = 20
MAX_SUMMARY_LENGTH = 2000
MAX_RECOMMENDATION_LENGTH = 1500

_SKIP_FIELDS = {"success", "tool", "source", "checked_at", "error"}

_NO_ROOT_CAUSE_SUMMARY = (
    "No verified root cause was established from the recorded tool results."
)
_NO_SAFE_RECOMMENDATION = (
    "No safe recommendation can be provided from the available tool results."
)
_NO_STEPS_RECOMMENDATION = (
    "No recommended steps were provided after the tool checks."
)


def _clip(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text
    return text[: max_length - 3].rstrip() + "..."


def _error_parts(entry: dict[str, Any]) -> tuple[str, str]:
    error = entry.get("error") or {}

    if isinstance(error, dict):
        code = str(error.get("code") or "TOOL_ERROR")
        message = str(error.get("message") or "Unknown error.")
        return code, message

    return "TOOL_ERROR", str(error)


def _format_value(value: Any) -> str | None:
    if value is None or value == "" or value == []:
        return None

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, list):
        rendered: list[str] = []

        for item in value[:5]:
            if isinstance(item, dict):
                label = item.get("id") or item.get("title")
                if label:
                    rendered.append(str(label))
            else:
                rendered.append(str(item))

        return ", ".join(rendered) if rendered else None

    if isinstance(value, dict):
        return None

    return str(value)


def _format_success(entry: dict[str, Any]) -> str:
    tool = str(entry.get("tool") or "unknown_tool")
    parts: list[str] = []

    for key, value in entry.items():
        if key in _SKIP_FIELDS:
            continue

        rendered = _format_value(value)
        if rendered is not None:
            parts.append(f"{key}={rendered}")

    if parts:
        return f"{tool}: " + "; ".join(parts)

    return f"{tool}: completed with no additional fields"


def _format_failure(entry: dict[str, Any]) -> str:
    tool = str(entry.get("tool") or "unknown_tool")
    code, message = _error_parts(entry)
    return f"{tool} failed: {code}: {message}"


def tool_log_to_evidence(
    tool_log: list[Any] | None,
) -> list[str]:
    """Format successful results and explicitly labeled failed attempts.

    Failed attempts are audit records, not successful technical evidence.
    """
    evidence: list[str] = []

    for entry in tool_log or []:
        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

        if not isinstance(entry, dict) or not entry.get("tool"):
            continue

        if entry.get("success") is True and entry.get("error") is None:
            evidence.append(_format_success(entry))
        else:
            evidence.append(_format_failure(entry))

    return evidence


def _summary_from_report(report: InvestigationReport) -> str:
    root_cause = (report.root_cause or "").strip()

    if len(root_cause) >= 10:
        return _clip(root_cause, MAX_SUMMARY_LENGTH)

    return _NO_ROOT_CAUSE_SUMMARY


def _recommendation_from_steps(
    steps: list[str],
) -> tuple[str, bool]:
    """Return (safe recommendation, whether any step was unsafe)."""
    safe_steps: list[str] = []
    had_unsafe = False

    for step in steps:
        if not isinstance(step, str) or not step.strip():
            continue

        safety = check_action_safety(step)

        if safety.allowed:
            safe_steps.append(step.strip())
        else:
            had_unsafe = True

    if not steps:
        return _NO_STEPS_RECOMMENDATION, False

    if not safe_steps:
        if had_unsafe:
            return _NO_SAFE_RECOMMENDATION, True

        return _NO_STEPS_RECOMMENDATION, False

    joined = " ".join(safe_steps)

    if len(joined) < 10:
        joined = f"Recommended steps: {joined}"

    return _clip(joined, MAX_RECOMMENDATION_LENGTH), had_unsafe


def report_to_investigation_result(
    report: InvestigationReport | dict[str, Any],
    tool_log: list[Any] | None = None,
) -> InvestigationResult:
    """Convert a report to the investigation result model safely."""
    if isinstance(report, dict):
        report = InvestigationReport.model_validate(report)

    log_entries = tool_log or []
    evidence = tool_log_to_evidence(log_entries)

    has_successful_evidence = any(
        isinstance(entry, dict)
        and entry.get("success") is True
        and entry.get("error") is None
        and bool(entry.get("tool"))
        for entry in log_entries
    )

    recommendation, had_unsafe = _recommendation_from_steps(
        report.recommended_steps
    )

    # Failed attempts remain visible for auditing, but cannot establish
    # a root cause or count as verified technical evidence.
    if not has_successful_evidence:
        return InvestigationResult(
            summary=_NO_ROOT_CAUSE_SUMMARY,
            evidence=evidence,
            recommendation=recommendation,
            requires_human_review=True,
        )

    return InvestigationResult(
        summary=_summary_from_report(report),
        evidence=evidence,
        recommendation=recommendation,
        requires_human_review=(
            report.needs_human_review or had_unsafe
        ),
    )
