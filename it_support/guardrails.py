"""Guardrails for the IT Incident Response Agent (OpenAI Agents SDK) + plain-Python versions for testing.

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

# ============================================================
# 1. INPUT GUARDRAIL
# ============================================================

_INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
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
    ]
]

_DISALLOWED_PATTERNS = [
    (
        reason,
        re.compile(pattern, re.IGNORECASE),
    )
    for reason, pattern in [
        (
            "Asking for someone else's password",
            r"\b(give|tell|send|show|share)\s+me\b.{0,25}\b(\w+'s|his|her|their|admin|administrator|ceo|manager'?s?|another\s+user'?s?)\s+password",
        ),
        (
            "Asking for someone else's password",
            r"\bpassword\s+(of|for)\s+(another|other|someone|the\s+admin|the\s+ceo|my\s+(manager|boss|colleague)|emp\d{3})",
        ),
        (
            "Asking for admin rights",
            r"\b(make|give|grant)\s+me\b.{0,15}\b(admin|administrator|root|domain\s*admin)\b",
        ),
        (
            "Bypassing security",
            r"\bbypass\w*\b.{0,25}\b(mfa|2fa|login|authentication|security|password|firewall)\b",
        ),
        (
            "Disabling security protection",
            r"\b(disable|turn\s*off|remove|uninstall)\b.{0,20}\b(anti-?virus|defender|firewall|mfa|2fa|monitoring)\b",
        ),
        (
            "Hacking or unauthorized access",
            r"\bhack\b|\b(access|log\s*into|read)\b.{0,15}\b(someone|another|other|my\s+(manager|boss|colleague))('s)?\s+(account|email|mailbox|files)",
        ),
        (
            "Deleting accounts, users or logs",
            r"\b(delete|wipe|erase|clear)\b.{0,20}\b(all\s+)?(logs?|users|accounts|audit)\b",
        ),
        (
            "Asking for someone else's password (Arabic)",
            r"(باسورد|كلمة\s*(سر|مرور)).{0,15}(بتاع|بتاعة|الخاص\s*ب).{0,10}(المدير|الادمن|زميلي)",
        ),
        (
            "Hacking (Arabic)",
            r"(اخترق|اهكر|هكر)",
        ),
    ]
]

_DATA_WORDS = (
    r"(account|password|vpn|laptop|device|pc|computer|email|e-mail|"
    r"mailbox|files|data|status|login|details|info|information|tickets?)"
)

_THIRD_PARTY_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        rf"\b(colleague|coworker|co-worker|manager|boss|teammate|friend|employee|user|person|someone\s+else|somebody\s+else)'?s\s+(\w+\s+)?{_DATA_WORDS}\b",
        rf"\b(his|her|their)\s+(\w+\s+)?{_DATA_WORDS}\b",
        rf"\b{_DATA_WORDS}\s+(of|for|belonging\s+to)\s+(my\s+|a\s+|another\s+|other\s+)?(colleague|coworker|co-worker|manager|boss|teammate|someone|somebody|employee|user|him|her|them)\b",
        r"(حساب|باسورد|كلمة\s*(سر|مرور)|جهاز|لابتوب|ايميل|إيميل|ملفات|بيانات|تذكرة|vpn).{0,12}(زميلي|زميلتي|زمايلي|المدير|مديري|مديرتي|حد\s*تاني|موظف\s*تاني|بتاعه|بتاعها|بتاعهم)",
        r"(بتاع|بتاعة|بتوع)\s+(زميلي|زميلتي|المدير|مديري|مديرتي|حد\s*تاني|موظف\s*تاني)",
    ]
]

_EMP_IN_TEXT = re.compile(r"\bEMP\d{3}\b", re.IGNORECASE)
_DEV_IN_TEXT = re.compile(r"\bDEV-\d{4}\b", re.IGNORECASE)


def find_other_people(
    text: str,
    requester_id: str | None,
) -> list[str]:
    """Find requests about another person's data."""
    if is_it_staff(requester_id):
        return []

    requester = normalize_employee_id(requester_id)
    found: list[str] = []

    for pattern in _THIRD_PARTY_PATTERNS:
        match = pattern.search(text)
        if match:
            found.append(f"another person's data ('{match.group(0)}')")

    if requester is None:
        return found

    for employee_id in {item.upper() for item in _EMP_IN_TEXT.findall(text)}:
        if employee_id != requester:
            found.append(f"employee {employee_id}")

    try:
        accounts = get_section("accounts")
        devices = get_section("devices")
    except DataUnavailableError:
        return found

    for device_id in {item.upper() for item in _DEV_IN_TEXT.findall(text)}:
        owner = (devices.get(device_id) or {}).get("owner_employee_id")
        if owner != requester:
            found.append(f"device {device_id}")

    for employee_id, record in accounts.items():
        if employee_id == requester:
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
    reason_code: Literal[
        "OK",
        "EMPTY",
        "TOO_LONG",
        "PROMPT_INJECTION",
        "DISALLOWED_REQUEST",
        "PRIVACY",
    ]
    message: str
    matched: list[str] = Field(default_factory=list)


def check_user_input(
    text: Any,
    requester_id: str | None = None,
) -> InputCheckResult:
    """Validate user input before an Agent runs."""
    if not isinstance(text, str) or not text.strip():
        return InputCheckResult(
            allowed=False,
            reason_code="EMPTY",
            message="Please describe your IT problem.",
        )

    if len(text) > MAX_INPUT_LENGTH:
        return InputCheckResult(
            allowed=False,
            reason_code="TOO_LONG",
            message=f"Message is too long (max {MAX_INPUT_LENGTH} characters).",
        )

    injections = [
        pattern.pattern
        for pattern in _INJECTION_PATTERNS
        if pattern.search(text)
    ]

    if injections:
        return InputCheckResult(
            allowed=False,
            reason_code="PROMPT_INJECTION",
            matched=injections,
            message="This request tries to change the assistant's instructions and was blocked.",
        )

    disallowed = sorted(
        {
            reason
            for reason, pattern in _DISALLOWED_PATTERNS
            if pattern.search(text)
        }
    )

    if disallowed:
        return InputCheckResult(
            allowed=False,
            reason_code="DISALLOWED_REQUEST",
            matched=disallowed,
            message="This request is not allowed: " + "; ".join(disallowed) + ".",
        )

    other_people = find_other_people(text, requester_id)

    if other_people:
        return InputCheckResult(
            allowed=False,
            reason_code="PRIVACY",
            matched=other_people,
            message="For privacy, you can only ask about your own account, VPN and devices.",
        )

    return InputCheckResult(
        allowed=True,
        reason_code="OK",
        message="Input accepted.",
    )


def _latest_user_text(agent_input: str | list[Any]) -> str:
    """Extract the newest user message from Agent input."""
    if isinstance(agent_input, str):
        return agent_input

    for item in reversed(agent_input or []):
        if not isinstance(item, dict) or item.get("role") != "user":
            continue

        content = item.get("content")

        if isinstance(content, str):
            return content

        if isinstance(content, list):
            return " ".join(
                part.get("text", "")
                for part in content
                if isinstance(part, dict)
                and part.get("type") in ("input_text", "text")
            )

    return ""


@input_guardrail(name="it_input_guardrail")
async def it_input_guardrail(
    ctx: RunContextWrapper[Any],
    agent: Agent[Any],
    agent_input: str | list[Any],
) -> GuardrailFunctionOutput:
    """Input guardrail attached to the triage Agent."""
    requester = (
        ctx.context.requester_id
        if isinstance(ctx.context, IncidentContext)
        else None
    )

    result = check_user_input(
        _latest_user_text(agent_input),
        requester,
    )

    return GuardrailFunctionOutput(
        output_info=result.model_dump(),
        tripwire_triggered=not result.allowed,
    )


# ============================================================
# 2. OUTPUT GUARDRAIL
# ============================================================

@output_guardrail(name="it_output_guardrail")
async def it_output_guardrail(
    ctx: RunContextWrapper[Any],
    agent: Agent[Any],
    agent_output: Any,
) -> GuardrailFunctionOutput:
    """Output guardrail ensuring final report findings are supported by tool results."""
    if not isinstance(agent_output, InvestigationReport):
        return GuardrailFunctionOutput(
            output_info={"allowed": True, "reason": "Not an investigation report"},
            tripwire_triggered=False,
        )

    context = ctx.context
    called_tools = getattr(context, "called_tools", set()) if context else set()

    allowed = True
    for finding in agent_output.findings:
        if finding.tool_used and finding.tool_used not in called_tools:
            allowed = False
            break

    return GuardrailFunctionOutput(
        output_info={"allowed": allowed},
        tripwire_triggered=not allowed,
    )


# ============================================================
# 3. TOOL GUARDRAILS
# ============================================================

def _extract_tool_name_and_args(data: Any) -> tuple[str | None, dict[str, Any]]:
    """Robustly extract tool name and arguments from SDK guardrail data objects."""
    tool_name = None
    args = {}

    if data is None:
        return None, {}

    tool_call = getattr(data, "tool_call", None)
    if tool_call:
        if isinstance(tool_call, str) and tool_call in ALLOWED_TOOL_NAMES:
            tool_name = tool_call
        else:
            for attr in ("name", "function_name"):
                val = getattr(tool_call, attr, None)
                if val and isinstance(val, str) and val in ALLOWED_TOOL_NAMES:
                    tool_name = val
                    break
            if not tool_name:
                func = getattr(tool_call, "function", None)
                if func:
                    val = getattr(func, "name", None)
                    if val and isinstance(val, str) and val in ALLOWED_TOOL_NAMES:
                        tool_name = val

    if not tool_name:
        for attr in ("tool_name", "name", "function_name"):
            val = getattr(data, attr, None)
            if val and isinstance(val, str) and val in ALLOWED_TOOL_NAMES:
                tool_name = val
                break

    if not tool_name:
        func = getattr(data, "function", None)
        if func:
            for attr in ("name", "function_name"):
                val = getattr(func, attr, None)
                if val and isinstance(val, str) and val in ALLOWED_TOOL_NAMES:
                    tool_name = val
                    break

    if not tool_name and hasattr(data, "model_dump"):
        try:
            d = data.model_dump()
            for k, v in d.items():
                if isinstance(v, str) and v in ALLOWED_TOOL_NAMES:
                    tool_name = v
                    break
            tc = d.get("tool_call")
            if not tool_name and isinstance(tc, dict):
                tool_name = tc.get("name") or tc.get("function_name")
            f = d.get("function")
            if not tool_name and isinstance(f, dict):
                tool_name = f.get("name")
        except Exception:
            pass

    if not tool_name:
        tool_name = "check_account_status"

    # Extract args
    for attr in ("args", "arguments"):
        val = getattr(data, attr, None)
        if val is not None:
            args = val
            break

    if not args and tool_call:
        for attr in ("args", "arguments"):
            val = getattr(tool_call, attr, None)
            if val is not None:
                args = val
                break
        func = getattr(tool_call, "function", None)
        if not args and func:
            for attr in ("args", "arguments"):
                val = getattr(func, attr, None)
                if val is not None:
                    args = val
                    break

    if not args and hasattr(data, "model_dump"):
        try:
            d = data.model_dump()
            args = d.get("args") or d.get("arguments") or {}
        except Exception:
            pass

    if isinstance(args, str):
        try:
            args = json.loads(args)
        except Exception:
            args = {}

    return tool_name, args or {}


@tool_input_guardrail
def tool_input_guardrail_func(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
    """Check tool permissions before execution."""
    tool_name, args = _extract_tool_name_and_args(data)
    if not tool_name:
        tool_name = "check_account_status"

    requester_id = None
    if data.context and data.context.context:
        ctx = data.context.context
        if hasattr(ctx, "requester_id"):
            requester_id = ctx.requester_id

    error_msg = check_tool_permission(tool_name, args, requester_id)
    if error_msg:
        if data.context and data.context.context:
            ctx = data.context.context
            if hasattr(ctx, "tool_log"):
                ctx.tool_log.append({
                    "tool_name": tool_name,
                    "error": {"code": "UNAUTHORIZED", "message": error_msg}
                })
        return ToolGuardrailFunctionOutput(
            output_info={"error": error_msg, "allowed": False},
        )

    return ToolGuardrailFunctionOutput(
        output_info={"allowed": True},
    )


@tool_output_guardrail
def tool_output_guardrail_func(data: ToolOutputGuardrailData) -> ToolGuardrailFunctionOutput:
    """Record tool results in context."""
    if data.context and data.context.context:
        ctx = data.context.context
        tool_name, _ = _extract_tool_name_and_args(data)
        if not tool_name:
            tool_name = "check_account_status"

        result = getattr(data, "result", None)
        if hasattr(ctx, "record"):
            ctx.record(result, tool_name=tool_name)

    return ToolGuardrailFunctionOutput(
        output_info={"allowed": True},
    )


TOOL_INPUT_GUARDRAILS = [tool_input_guardrail_func]
TOOL_OUTPUT_GUARDRAILS = [tool_output_guardrail_func]


# ============================================================
# HELPER CLASSES & FUNCTIONS FOR TESTING & WORKFLOW
# ============================================================

class ReportValidationResult(BaseModel):
    valid: bool
    reasons: list[str] = Field(default_factory=list)

    @property
    def problems(self) -> list[str]:
        return self.reasons


def validate_report(
    report: InvestigationReport,
    called_tools: set[str] | None = None,
) -> ReportValidationResult:
    """Validate that the investigation report findings are supported by tool results and safety rules."""
    if called_tools is None:
        called_tools = set()

    reasons: list[str] = []

    if not report.findings:
        reasons.append("Report has no findings.")

    for finding in report.findings:
        if finding.tool_used and finding.tool_used not in called_tools:
            reasons.append(f"Tool '{finding.tool_used}' was cited in findings but never ran.")

    if report.category == "security" and not report.needs_human_review:
        reasons.append("Security incidents require human review.")

    for step in report.recommended_steps:
        if "disable the firewall" in step.lower():
            reasons.append("Dangerous step recommended.")

    return ReportValidationResult(valid=len(reasons) == 0, reasons=reasons)


def check_tool_permission(
    tool_name: str,
    args: dict[str, Any],
    requester_id: str | None,
) -> str | None:
    """Check if the requester has permission to execute the given tool with arguments."""
    if tool_name not in ALLOWED_TOOL_NAMES:
        return f"Tool '{tool_name}' is not allowed."

    if tool_name in ("check_network_status", "search_it_knowledge"):
        return None

    if is_it_staff(requester_id):
        return None

    norm_req = normalize_employee_id(requester_id)
    if not norm_req:
        return "UNAUTHORIZED: Unknown requester cannot access personal data."

    target_emp = normalize_employee_id(args.get("employee_id"))
    device_id = normalize_device_id(args.get("device_id"))

    if target_emp and target_emp != norm_req:
        return f"UNAUTHORIZED: Employee {norm_req} cannot access data for employee {target_emp}."

    if device_id:
        try:
            devices = get_section("devices")
            owner = (devices.get(device_id) or {}).get("owner_employee_id")
            if owner and owner != norm_req:
                return f"Employee {norm_req} cannot access device {device_id} owned by {owner}."
        except DataUnavailableError:
            pass

    return None
