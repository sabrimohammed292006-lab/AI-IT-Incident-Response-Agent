"""Guardrails for the Agents (OpenAI Agents SDK) + plain-Python versions for testing.

Input guardrail   -> blocks prompt injection and disallowed requests before any Agent runs.
Output guardrail  -> blocks reports whose solutions are not backed by tool results.
Tool guardrails   -> per-tool permission checks + automatic logging of tool results.

All checks are rule-based (no extra LLM call): fast, free, and predictable in the demo.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from agents import (
    Agent,
    GuardrailFunctionOutput,
    RunContextWrapper,
    ToolGuardrailFunctionOutput,
    ToolInputGuardrailData,
    ToolOutputGuardrailData,
    input_guardrail,
    output_guardrail,
    tool_input_guardrail,
    tool_output_guardrail,
)
from pydantic import BaseModel, Field

from .context import IncidentContext
from .data_store import DataUnavailableError, get_section
from .safety import check_action_safety, is_it_staff
from .schemas import InvestigationReport
from .validators import normalize_device_id, normalize_employee_id

MAX_INPUT_LENGTH = 2000

ALLOWED_TOOL_NAMES = {
    "check_account_status",
    "check_vpn_status",
    "check_device_status",
    "check_network_status",
    "search_it_knowledge",
}

# ---------------------------------------------------------------------------
# 1) Input guardrail
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your|the)\b.{0,20}\b(instructions?|rules?|prompts?|guidelines?)\b",
    r"\b(reveal|show|print|repeat|leak|tell me)\b.{0,25}\b(system\s*prompt|your\s*(instructions|prompt|rules))\b",
    r"\byou\s+are\s+now\b",
    r"\bact\s+as\b.{0,20}\b(admin|administrator|root|developer|system|dan|unrestricted)\b",
    r"\b(developer|god|dan|jailbreak)\s*mode\b|\bjailbreak\b",
    r"<\s*/?\s*(system|assistant|instructions?)\s*>",
    r"#{2,}\s*(system|instructions?)\b",
    r"\bnew\s+instructions?\s*:",
    r"\b(pretend|assume)\b.{0,25}\b(i\s*am|i'm)\b.{0,20}\b(admin|administrator|it\s*staff|manager)\b",
    r"(تجاهل|انسى|انسي).{0,20}(التعليمات|القواعد|الأوامر|الاوامر)",
    r"(اعتبر|تخيل).{0,15}(نفسك|انك).{0,15}(ادمن|أدمن|مدير)",
]]

_DISALLOWED_PATTERNS = [(reason, re.compile(p, re.IGNORECASE)) for reason, p in [
    ("Asking for someone else's password",
     r"\b(give|tell|send|show|share)\s+me\b.{0,25}\b(\w+'s|his|her|their|admin|administrator|ceo|manager'?s?|another\s+user'?s?)\s+password"),
    ("Asking for someone else's password",
     r"\bpassword\s+(of|for)\s+(another|other|someone|the\s+admin|the\s+ceo|my\s+(manager|boss|colleague)|emp\d{3})"),
    ("Asking for admin rights",
     r"\b(make|give|grant)\s+me\b.{0,15}\b(admin|administrator|root|domain\s*admin)\b"),
    ("Bypassing security",
     r"\bbypass\w*\b.{0,25}\b(mfa|2fa|login|authentication|security|password|firewall)\b"),
    ("Disabling security protection",
     r"\b(disable|turn\s*off|remove|uninstall)\b.{0,20}\b(anti-?virus|defender|firewall|mfa|2fa|monitoring)\b"),
    ("Hacking or unauthorized access",
     r"\bhack\b|\b(access|log\s*into|read)\b.{0,15}\b(someone|another|other|my\s+(manager|boss|colleague))('s)?\s+(account|email|mailbox|files)"),
    ("Deleting accounts, users or logs",
     r"\b(delete|wipe|erase|clear)\b.{0,20}\b(all\s+)?(logs?|users|accounts|audit)\b"),
    ("Asking for someone else's password (Arabic)",
     r"(باسورد|كلمة\s*(سر|مرور)).{0,15}(بتاع|بتاعة|الخاص\s*ب).{0,10}(المدير|الادمن|زميلي)"),
    ("Hacking (Arabic)", r"(اخترق|اهكر|هكر)"),
]]


# Requests about another person's data, phrased without naming them.
_DATA_WORDS = (r"(account|password|vpn|laptop|device|pc|computer|email|e-mail|mailbox|files|data|"
               r"status|login|details|info|information|tickets?)")
_THIRD_PARTY_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    rf"\b(colleague|coworker|co-worker|manager|boss|teammate|friend|employee|user|person|someone\s+else|"
    rf"somebody\s+else)'?s\s+(\w+\s+)?{_DATA_WORDS}\b",
    rf"\b(his|her|their)\s+(\w+\s+)?{_DATA_WORDS}\b",
    rf"\b{_DATA_WORDS}\s+(of|for|belonging\s+to)\s+(my\s+|a\s+|another\s+|other\s+)?"
    rf"(colleague|coworker|co-worker|manager|boss|teammate|someone|somebody|employee|user|him|her|them)\b",
    r"(حساب|باسورد|كلمة\s*(سر|مرور)|جهاز|لابتوب|ايميل|إيميل|ملفات|بيانات|تذكرة|vpn).{0,12}"
    r"(زميلي|زميلتي|زمايلي|المدير|مديري|مديرتي|حد\s*تاني|موظف\s*تاني|بتاعه|بتاعها|بتاعهم)",
    r"(بتاع|بتاعة|بتوع)\s+(زميلي|زميلتي|المدير|مديري|مديرتي|حد\s*تاني|موظف\s*تاني)",
]]

_EMP_IN_TEXT = re.compile(r"\bEMP\d{3}\b", re.IGNORECASE)
_DEV_IN_TEXT = re.compile(r"\bDEV-\d{4}\b", re.IGNORECASE)


def find_other_people(text: str, requester_id: str | None) -> list[str]:
    """List every other person this message asks about (by ID, device, name or description).

    IT staff may ask about anyone, so they always get an empty list.
    If the requester is unknown we still catch descriptions ("my colleague's laptop"),
    but cannot tell whose ID is whose; the tool guardrail then blocks personal lookups.
    """
    if is_it_staff(requester_id):
        return []
    requester = normalize_employee_id(requester_id)
    found: list[str] = []

    for p in _THIRD_PARTY_PATTERNS:
        m = p.search(text)
        if m:
            found.append(f"another person's data ('{m.group(0)}')")

    if requester is None:
        return found

    for emp in {e.upper() for e in _EMP_IN_TEXT.findall(text)}:
        if emp != requester:
            found.append(f"employee {emp}")

    try:
        accounts = get_section("accounts")
        devices = get_section("devices")
    except DataUnavailableError:
        return found

    for dev in {d.upper() for d in _DEV_IN_TEXT.findall(text)}:
        owner = (devices.get(dev) or {}).get("owner_employee_id")
        if owner != requester:
            found.append(f"device {dev}")

    for emp_id, record in accounts.items():
        if emp_id == requester:
            continue
        full_name = record.get("name", "")
        first_name = full_name.split()[0] if full_name else ""
        for name in (full_name, first_name):
            if name and re.search(rf"\b{re.escape(name)}\b", text, re.IGNORECASE):
                found.append(f"employee '{name}'")
                break
    return found


class InputCheckResult(BaseModel):
    allowed: bool
    reason_code: Literal["OK", "EMPTY", "TOO_LONG", "PROMPT_INJECTION", "DISALLOWED_REQUEST",
                         "PRIVACY"]
    message: str
    matched: list[str] = Field(default_factory=list)


def check_user_input(text: Any, requester_id: str | None = None) -> InputCheckResult:
    """Plain-Python input check (also used by the Gradio app before calling Agents).

    requester_id must come from the login, never from the message text.
    """
    if not isinstance(text, str) or not text.strip():
        return InputCheckResult(allowed=False, reason_code="EMPTY",
                                message="Please describe your IT problem.")
    if len(text) > MAX_INPUT_LENGTH:
        return InputCheckResult(allowed=False, reason_code="TOO_LONG",
                                message=f"Message is too long (max {MAX_INPUT_LENGTH} characters).")

    injections = [p.pattern for p in _INJECTION_PATTERNS if p.search(text)]
    if injections:
        return InputCheckResult(
            allowed=False, reason_code="PROMPT_INJECTION", matched=injections,
            message="This request tries to change the assistant's instructions and was blocked.")

    disallowed = sorted({reason for reason, p in _DISALLOWED_PATTERNS if p.search(text)})
    if disallowed:
        return InputCheckResult(
            allowed=False, reason_code="DISALLOWED_REQUEST", matched=disallowed,
            message="This request is not allowed: " + "; ".join(disallowed) + ".")

    others = find_other_people(text, requester_id)
    if others:
        return InputCheckResult(
            allowed=False, reason_code="PRIVACY", matched=others,
            message="For privacy, you can only ask about your own account, VPN and devices. "
                    "If a colleague has a problem, they need to report it themselves.")

    return InputCheckResult(allowed=True, reason_code="OK", message="Input accepted.")


def _latest_user_text(agent_input: str | list[Any]) -> str:
    """Get the newest user message from the Agent input (string or message list)."""
    if isinstance(agent_input, str):
        return agent_input
    for item in reversed(agent_input or []):
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        content = item.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return " ".join(part.get("text", "") for part in content
                            if isinstance(part, dict) and part.get("type") in ("input_text", "text"))
    return ""


@input_guardrail(name="it_input_guardrail")
async def it_input_guardrail(
    ctx: RunContextWrapper[Any], agent: Agent[Any], agent_input: str | list[Any]
) -> GuardrailFunctionOutput:
    """Attach to the first Agent (Triage): Agent(..., input_guardrails=[it_input_guardrail])."""
    requester = ctx.context.requester_id if isinstance(ctx.context, IncidentContext) else None
    result = check_user_input(_latest_user_text(agent_input), requester)
    return GuardrailFunctionOutput(output_info=result.model_dump(),
                                   tripwire_triggered=not result.allowed)


# ---------------------------------------------------------------------------
# 2) Output guardrail
# ---------------------------------------------------------------------------


class ReportCheckResult(BaseModel):
    valid: bool
    problems: list[str] = Field(default_factory=list)


def validate_report(report: InvestigationReport | dict,
                    called_tools: set[str] | None = None) -> ReportCheckResult:
    """Check that the report only claims what the tools actually showed.

    called_tools: names of tools that ran successfully. If given, every finding
    must cite one of them (a finding from a tool that never ran is invented).
    """
    if isinstance(report, dict):
        report = InvestigationReport.model_validate(report)
    problems: list[str] = []

    if not report.findings and (report.recommended_steps or report.root_cause):
        problems.append("Report gives a root cause or steps without any tool-backed findings.")

    for f in report.findings:
        if f.tool_used not in ALLOWED_TOOL_NAMES:
            problems.append(f"Finding cites unknown tool '{f.tool_used}'.")
        elif called_tools is not None and f.tool_used not in called_tools:
            problems.append(f"Finding cites '{f.tool_used}', but that tool did not return data.")
        if not f.observation.strip():
            problems.append(f"Finding from '{f.tool_used}' has an empty observation.")

    for step in report.recommended_steps:
        safety = check_action_safety(step)
        if not safety.allowed:
            problems.append(f"Unsafe step '{step}': " + "; ".join(safety.violations))

    if report.category == "security" and not report.needs_human_review:
        problems.append("Security incidents must be marked for human review.")
    if report.severity == "critical" and not report.needs_human_review:
        problems.append("Critical incidents must be marked for human review.")

    return ReportCheckResult(valid=not problems, problems=problems)


@output_guardrail(name="it_output_guardrail")
async def it_output_guardrail(
    ctx: RunContextWrapper[Any], agent: Agent[Any], output: Any
) -> GuardrailFunctionOutput:
    """Attach to the Agent whose output_type is InvestigationReport."""
    called = ctx.context.called_tools if isinstance(ctx.context, IncidentContext) else None
    try:
        result = validate_report(output, called)
    except Exception as exc:  # output is not a valid InvestigationReport
        result = ReportCheckResult(valid=False, problems=[f"Invalid report format: {exc}"])
    return GuardrailFunctionOutput(output_info=result.model_dump(),
                                   tripwire_triggered=not result.valid)


# ---------------------------------------------------------------------------
# 3) Tool-level guardrails
# ---------------------------------------------------------------------------


def _tool_args(data: ToolInputGuardrailData) -> dict:
    try:
        args = json.loads(data.context.tool_arguments or "{}")
        return args if isinstance(args, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def check_tool_permission(tool_name: str, args: dict, requester_id: str | None) -> str | None:
    """Return a reason string if the requester may NOT run this tool with these args.

    Rule: normal employees may only check their own account, VPN and devices.
    IT staff may check anyone. Network status and knowledge search are open to all.
    If no requester is known, we cannot authorize personal checks.
    """
    if tool_name in ("check_network_status", "search_it_knowledge"):
        return None
    if is_it_staff(requester_id):
        return None
    requester = normalize_employee_id(requester_id)
    if requester is None:
        return "Requester is not identified, so personal account/device data cannot be checked."

    if tool_name in ("check_account_status", "check_vpn_status"):
        target = normalize_employee_id(args.get("employee_id"))
        if target is not None and target != requester:
            return f"{requester} is not allowed to check another employee's data ({target})."
    elif tool_name == "check_device_status":
        dev = normalize_device_id(args.get("device_id"))
        if dev is not None:
            try:
                owner = (get_section("devices").get(dev) or {}).get("owner_employee_id")
            except DataUnavailableError:
                owner = None
            if owner is not None and owner != requester:
                return f"{requester} is not allowed to check device {dev} (not their device)."
    return None


@tool_input_guardrail(name="it_tool_permission_guardrail")
def it_tool_permission_guardrail(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
    """Runs before every check tool. Blocks unauthorized lookups.

    Fails closed: if the run has no IncidentContext, we don't know who is asking,
    so personal data (account, VPN, device) is never returned.
    """
    ctx = data.context.context
    requester = ctx.requester_id if isinstance(ctx, IncidentContext) else None
    reason = check_tool_permission(data.context.tool_name, _tool_args(data), requester)
    if reason:
        if isinstance(ctx, IncidentContext):
            ctx.tool_log.append({"tool": data.context.tool_name, "success": False,
                                 "error": {"code": "UNAUTHORIZED", "message": reason}})
        return ToolGuardrailFunctionOutput.reject_content(
            f"UNAUTHORIZED: {reason} Do not retry; tell the user an IT staff member must check this.")
    return ToolGuardrailFunctionOutput.allow()


@tool_output_guardrail(name="it_tool_audit_guardrail")
def it_tool_audit_guardrail(data: ToolOutputGuardrailData) -> ToolGuardrailFunctionOutput:
    """Runs after every tool. Records the result so the output guardrail can verify findings."""
    ctx = data.context.context
    if isinstance(ctx, IncidentContext):
        ctx.record(data.output)
    return ToolGuardrailFunctionOutput.allow()


TOOL_INPUT_GUARDRAILS = [it_tool_permission_guardrail]
TOOL_OUTPUT_GUARDRAILS = [it_tool_audit_guardrail]
