"""Python safety rules. These run in code, not in the LLM, so they cannot be talked around.

1. evaluate_escalation()  -> decides if a human must review the incident.
2. check_action_safety()  -> blocks dangerous actions in any recommended step.
3. is_it_staff()          -> who is allowed to do what.
"""

from __future__ import annotations

import re
from typing import Iterable

from pydantic import BaseModel, Field

from .data_store import DataUnavailableError, get_section
from .schemas import Severity, max_severity
from .validators import normalize_employee_id

BRUTE_FORCE_THRESHOLD = 10  # failed logins that look like an attack, not a forgotten password


# ---------------------------------------------------------------------------
# Who is who
# ---------------------------------------------------------------------------


def is_it_staff(employee_id: str | None) -> bool:
    """True if the employee works in the IT department (from the mock data)."""
    emp = normalize_employee_id(employee_id)
    if emp is None:
        return False
    try:
        record = get_section("accounts").get(emp)
    except DataUnavailableError:
        return False  # fail closed: if we can't verify, no extra rights
    return bool(record) and record.get("department") == "IT" and record.get("account_status") == "active"


def employee_exists(employee_id: str | None) -> bool:
    emp = normalize_employee_id(employee_id)
    if emp is None:
        return False
    try:
        return emp in get_section("accounts")
    except DataUnavailableError:
        return False


# ---------------------------------------------------------------------------
# 1) Escalation rules
# ---------------------------------------------------------------------------


class EscalationDecision(BaseModel):
    needs_human_review: bool
    final_severity: Severity
    reasons: list[str] = Field(default_factory=list)
    allow_auto_close: bool = False


def evaluate_escalation(
    category: str,
    severity: Severity,
    tool_results: Iterable[dict],
    security_indicators: Iterable[str] = (),
) -> EscalationDecision:
    """Apply the escalation rules to the triage + tool results.

    Severity can only be raised by these rules, never lowered.
    Security and critical incidents are never auto-closed.
    """
    reasons: list[str] = []
    final = severity

    def escalate(new_severity: str, reason: str) -> None:
        nonlocal final
        final = max_severity(final, new_severity)
        reasons.append(reason)

    indicators = [i for i in security_indicators if i and i.strip()]
    if category == "security":
        escalate("critical", "Incident is classified as a security incident.")
    if indicators:
        escalate("critical", "Security indicators reported: " + "; ".join(indicators))

    for r in tool_results:
        if not isinstance(r, dict):
            continue
        tool = r.get("tool")
        error = r.get("error") or {}

        if not r.get("success"):
            if error.get("code") in ("DATA_UNAVAILABLE", "TOOL_ERROR"):
                escalate("medium", f"{tool} could not run ({error.get('message')}); "
                                   "result cannot be verified automatically.")
            continue

        if tool == "check_device_status":
            if r.get("security_alerts"):
                escalate("critical", f"Device {r.get('device_id')} has security alerts: "
                                     + "; ".join(r["security_alerts"]))
            if r.get("antivirus_status") == "disabled":
                escalate("high", f"Antivirus is disabled on {r.get('device_id')}.")
        elif tool == "check_account_status":
            if r.get("account_status") == "disabled":
                escalate("high", f"Account {r.get('employee_id')} is disabled; re-enabling needs "
                                 "HR/security approval.")
            if (r.get("failed_login_attempts") or 0) >= BRUTE_FORCE_THRESHOLD:
                escalate("critical", f"{r.get('failed_login_attempts')} failed logins on "
                                     f"{r.get('employee_id')}: possible brute-force attack.")
        elif tool == "check_network_status":
            if r.get("network_status") == "down":
                outage = r.get("active_outage_id")
                escalate("high", f"Site {r.get('site')} network is down"
                                 + (f" (outage {outage})." if outage else "."))

    if final == "critical" and not any("critical" in x.lower() for x in reasons):
        reasons.append("Severity is critical.")

    needs_review = final in ("high", "critical") or bool(reasons)
    return EscalationDecision(
        needs_human_review=needs_review,
        final_severity=final,
        reasons=reasons,
        allow_auto_close=(not needs_review and final == "low"),
    )


# ---------------------------------------------------------------------------
# 2) Dangerous actions
# ---------------------------------------------------------------------------

DANGEROUS_ACTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    (reason, re.compile(pattern, re.IGNORECASE))
    for reason, pattern in [
        ("Turning off security protection",
         r"\b(disable|turn\s*off|deactivate|uninstall|stop|kill)\b.{0,25}\b(anti-?virus|defender|firewall|edr|mfa|2fa|security)\b"),
        ("Bypassing authentication",
         r"\bbypass\w*\b.{0,25}\b(mfa|2fa|login|authentication|security|password|vpn)\b"),
        ("Deleting users, accounts or logs",
         r"\b(delete|remove|wipe|erase|clear)\b.{0,20}\b(user|users|account|accounts|logs?|audit|event\s*log)\b"),
        ("Formatting or wiping a disk",
         r"\b(format|wipe|erase)\b.{0,20}\b(disk|drive|hard\s*drive|ssd|c:)|\bdiskpart\b"),
        ("Destructive shell command",
         r"rm\s+-rf|del\s+/[sfq]|rd\s+/s|mkfs|dd\s+if="),
        ("Granting admin privileges",
         r"\b(grant|give|add|assign|make)\b.{0,25}\b(admin|administrator|root|sudo|domain\s*admin)\b"),
        ("Sharing passwords or credentials",
         r"\b(share|send|tell|give|email|post|paste)\s+(me\s+|us\s+|it\s+)?"
         r"(your|my|the|his|her|their|user'?s|employee'?s)?\s*(password|credentials|otp|mfa\s*code)\b"
         r"|\b(password|credentials|otp)\b.{0,25}\b(to\s+(the\s+)?(it\s+team|support|someone|me)|by\s+email|via\s+(email|chat))\b"),
        ("Editing the registry",
         r"\bregedit\b|\b(edit|modify|change|delete)\b.{0,15}\bregistry\b"),
        ("Disabling certificate checks",
         r"\b(disable|ignore|skip)\b.{0,25}\b(certificate|ssl|tls)\b"),
        ("Paying a ransom", r"\bpay\b.{0,15}\bransom\b"),
        ("Turning off security protection (Arabic)",
         r"(اقفل|عطل|الغي|وقف).{0,15}(الانتي\s*فايرس|الفايروول|الحماية)"),
        ("Deleting data (Arabic)", r"(امسح|احذف).{0,15}(الحسابات|المستخدمين|اللوجز|الهارد)"),
    ]
]


class SafetyCheck(BaseModel):
    allowed: bool
    violations: list[str] = Field(default_factory=list)


def check_action_safety(text: str) -> SafetyCheck:
    """Check one action/step text against the dangerous-action rules."""
    if not isinstance(text, str):
        return SafetyCheck(allowed=False, violations=["Action is not text."])
    violations = [reason for reason, pattern in DANGEROUS_ACTION_PATTERNS if pattern.search(text)]
    return SafetyCheck(allowed=not violations, violations=violations)
