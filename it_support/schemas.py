"""Shared Pydantic models (the contract between the Tools part and the Agents part).

Two groups of models live here:
1. Tool results  -> what every check_* / search tool returns.
2. Shared models -> what the Agents produce (Triage, Findings, Report).
   These MUST be agreed with the teammate building the Agents before changing them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Shared vocabulary
# ---------------------------------------------------------------------------

Category = Literal["account", "vpn", "device", "network", "security", "other"]
Severity = Literal["low", "medium", "high", "critical"]
ErrorCode = Literal["INVALID_INPUT", "NOT_FOUND", "DATA_UNAVAILABLE", "UNAUTHORIZED", "TOOL_ERROR"]

SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def max_severity(a: str, b: str) -> str:
    """Return the more severe of two severities (severity can only go up)."""
    return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b


def utc_now() -> str:
    """Current UTC time as an ISO string (used to timestamp every check)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# 1) Tool results
# ---------------------------------------------------------------------------


class ToolError(BaseModel):
    """Why a tool could not return data. Agents must never guess past this."""

    code: ErrorCode
    message: str


class BaseToolResult(BaseModel):
    """Fields every tool result shares."""

    success: bool
    tool: str
    source: str = "mock_data"
    checked_at: str = Field(default_factory=utc_now)
    error: ToolError | None = None


class AccountStatusResult(BaseToolResult):
    tool: str = "check_account_status"
    employee_id: str | None = None
    account_status: Literal["active", "locked", "disabled", "password_expired"] | None = None
    failed_login_attempts: int | None = None
    password_expires_in_days: int | None = None
    mfa_enabled: bool | None = None
    last_login: str | None = None


class VpnStatusResult(BaseToolResult):
    tool: str = "check_vpn_status"
    employee_id: str | None = None
    vpn_status: Literal["connected", "disconnected", "auth_failed", "error"] | None = None
    last_error: str | None = None
    client_version: str | None = None
    client_up_to_date: bool | None = None
    certificate_valid: bool | None = None


class DeviceStatusResult(BaseToolResult):
    tool: str = "check_device_status"
    device_id: str | None = None
    owner_employee_id: str | None = None
    os: str | None = None
    device_status: Literal["online", "offline"] | None = None
    disk_free_percent: int | None = None
    antivirus_status: Literal["healthy", "outdated", "disabled"] | None = None
    last_patch_date: str | None = None
    security_alerts: list[str] = Field(default_factory=list)


class NetworkStatusResult(BaseToolResult):
    tool: str = "check_network_status"
    site: str | None = None
    network_status: Literal["up", "degraded", "down"] | None = None
    latency_ms: int | None = None
    packet_loss_percent: float | None = None
    active_outage_id: str | None = None


# ---------------------------------------------------------------------------
# 2) Shared models with the Agents part (agree with teammate before editing)
# ---------------------------------------------------------------------------


class TriageResult(BaseModel):
    """Output of the Triage Agent."""

    category: Category
    severity: Severity
    summary: str = Field(description="One-sentence summary of the reported problem.")
    employee_id: str | None = Field(description="Employee ID like EMP001, or null if not given.")
    device_id: str | None = Field(description="Device ID like DEV-1001, or null if not given.")
    site: str | None = Field(description="Office site like CAIRO-HQ, or null if not given.")
    security_indicators: list[str] = Field(
        description="Signs of a security incident (phishing, malware, data leak...). Empty if none."
    )


class Finding(BaseModel):
    """One fact a Worker Agent confirmed using a tool."""

    tool_used: str = Field(description="Name of the tool whose result supports this finding.")
    observation: str = Field(description="What the tool result showed, stated factually.")


class InvestigationReport(BaseModel):
    """Final output the Agents hand back to the Python workflow."""

    category: Category
    severity: Severity
    findings: list[Finding]
    root_cause: str | None = Field(description="Root cause supported by findings, or null if unknown.")
    recommended_steps: list[str] = Field(description="Steps for the employee/IT, backed by findings.")
    needs_human_review: bool
