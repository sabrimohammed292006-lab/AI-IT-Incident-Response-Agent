"""The four read-only check tools.

Each tool is a plain Python function (easy to test), then wrapped with
function_tool() so the Agents can call it. All tools:
  * validate input before reading data,
  * never invent a value that is not in the data,
  * return a structured error instead of crashing.
"""

from __future__ import annotations

import functools
from typing import Any

from agents import function_tool

from .data_store import DataUnavailableError, get_section, load_json, SYSTEMS_FILE
from .guardrails import TOOL_INPUT_GUARDRAILS, TOOL_OUTPUT_GUARDRAILS
from .schemas import (
    AccountStatusResult,
    DeviceStatusResult,
    NetworkStatusResult,
    ToolError,
    VpnStatusResult,
)
from .validators import normalize_device_id, normalize_employee_id, normalize_site


def _error(result_cls, code: str, message: str, **fields: Any) -> dict:
    """Build a failed result of the right type."""
    return result_cls(success=False, error=ToolError(code=code, message=message), **fields).model_dump()


def safe_tool(result_cls):
    """Decorator: any unexpected crash becomes a TOOL_ERROR result instead of an exception."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as exc:  # last line of defence
                return _error(result_cls, "TOOL_ERROR",
                              f"{fn.__name__} failed unexpectedly ({type(exc).__name__}).")
        return wrapper
    return decorator


def make_agent_tool(fn):
    """Wrap a plain function as a Function Tool with our tool-level guardrails attached."""
    return function_tool(fn, tool_input_guardrails=TOOL_INPUT_GUARDRAILS,
                         tool_output_guardrails=TOOL_OUTPUT_GUARDRAILS)


# ---------------------------------------------------------------------------
# 1) Account
# ---------------------------------------------------------------------------


@safe_tool(AccountStatusResult)
def check_account_status(employee_id: str) -> dict:
    """Check an employee's account status (read-only, never changes it).

    Returns whether the account is active, locked, disabled or has an expired password,
    plus failed login attempts and MFA status.

    Args:
        employee_id: The employee ID, for example "EMP002".
    """
    emp = normalize_employee_id(employee_id)
    if emp is None:
        return _error(AccountStatusResult, "INVALID_INPUT",
                      "Employee ID must look like EMP001.")
    try:
        record = get_section("accounts").get(emp)
    except DataUnavailableError as exc:
        return _error(AccountStatusResult, "DATA_UNAVAILABLE", str(exc), employee_id=emp)
    if record is None:
        return _error(AccountStatusResult, "NOT_FOUND",
                      f"No account found for {emp}.", employee_id=emp)

    return AccountStatusResult(
        success=True,
        employee_id=emp,
        account_status=record["account_status"],
        failed_login_attempts=record["failed_login_attempts"],
        password_expires_in_days=record["password_expires_in_days"],
        mfa_enabled=record["mfa_enabled"],
        last_login=record["last_login"],
    ).model_dump()


# ---------------------------------------------------------------------------
# 2) VPN
# ---------------------------------------------------------------------------


@safe_tool(VpnStatusResult)
def check_vpn_status(employee_id: str) -> dict:
    """Check an employee's VPN connection status (read-only).

    Returns the VPN state, the last VPN error, the client version and
    whether the VPN certificate is valid.

    Args:
        employee_id: The employee ID, for example "EMP006".
    """
    emp = normalize_employee_id(employee_id)
    if emp is None:
        return _error(VpnStatusResult, "INVALID_INPUT",
                      "Employee ID must look like EMP001.")
    try:
        record = get_section("vpn").get(emp)
        latest = load_json(SYSTEMS_FILE).get("latest_vpn_client_version")
    except DataUnavailableError as exc:
        return _error(VpnStatusResult, "DATA_UNAVAILABLE", str(exc), employee_id=emp)
    if record is None:
        return _error(VpnStatusResult, "NOT_FOUND",
                      f"No VPN record found for {emp}. The VPN status is unknown.",
                      employee_id=emp)

    return VpnStatusResult(
        success=True,
        employee_id=emp,
        vpn_status=record["vpn_status"],
        last_error=record["last_error"],
        client_version=record["client_version"],
        client_up_to_date=(record["client_version"] == latest) if latest else None,
        certificate_valid=record["certificate_valid"],
    ).model_dump()


# ---------------------------------------------------------------------------
# 3) Device
# ---------------------------------------------------------------------------


@safe_tool(DeviceStatusResult)
def check_device_status(device_id: str) -> dict:
    """Check a device's health and security status (read-only).

    Returns online/offline, free disk space, antivirus state, last patch date
    and any active security alerts.

    Args:
        device_id: The device ID, for example "DEV-1001".
    """
    dev = normalize_device_id(device_id)
    if dev is None:
        return _error(DeviceStatusResult, "INVALID_INPUT",
                      "Device ID must look like DEV-1001.")
    try:
        record = get_section("devices").get(dev)
    except DataUnavailableError as exc:
        return _error(DeviceStatusResult, "DATA_UNAVAILABLE", str(exc), device_id=dev)
    if record is None:
        return _error(DeviceStatusResult, "NOT_FOUND",
                      f"No device found with ID {dev}.", device_id=dev)

    return DeviceStatusResult(success=True, device_id=dev, **record).model_dump()


# ---------------------------------------------------------------------------
# 4) Network
# ---------------------------------------------------------------------------


@safe_tool(NetworkStatusResult)
def check_network_status(site: str) -> dict:
    """Check the network status of an office site (read-only).

    Returns up/degraded/down, latency, packet loss and any active outage ID.

    Args:
        site: The office site name, for example "CAIRO-HQ" or "ALEX-BRANCH".
    """
    name = normalize_site(site)
    if name is None:
        return _error(NetworkStatusResult, "INVALID_INPUT",
                      "Site must be a name like CAIRO-HQ.")
    try:
        offline = load_json(SYSTEMS_FILE).get("_monitoring_offline_sites", [])
        if name in offline:
            raise DataUnavailableError(
                f"Network monitoring for {name} is offline. Status cannot be confirmed."
            )
        record = get_section("network_sites").get(name)
    except DataUnavailableError as exc:
        return _error(NetworkStatusResult, "DATA_UNAVAILABLE", str(exc), site=name)
    if record is None:
        return _error(NetworkStatusResult, "NOT_FOUND",
                      f"Unknown site {name}.", site=name)

    return NetworkStatusResult(success=True, site=name, **record).model_dump()


# ---------------------------------------------------------------------------
# Function Tools for the Agents (teammate imports these)
# ---------------------------------------------------------------------------

check_account_status_tool = make_agent_tool(check_account_status)
check_vpn_status_tool = make_agent_tool(check_vpn_status)
check_device_status_tool = make_agent_tool(check_device_status)
check_network_status_tool = make_agent_tool(check_network_status)

CHECK_TOOLS = [
    check_account_status_tool,
    check_vpn_status_tool,
    check_device_status_tool,
    check_network_status_tool,
]


if __name__ == "__main__":
    # Quick manual demo: python -m it_support.check_tools
    import json

    demos = [
        check_account_status("EMP002"),
        check_vpn_status("emp005"),
        check_device_status("DEV-1003"),
        check_network_status("giza office"),
        check_network_status("ASWAN-BRANCH"),
        check_account_status("EMP999"),
        check_account_status("'; DROP TABLE users; --"),
    ]
    for result in demos:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print("-" * 60)

    for t in CHECK_TOOLS:
        print("Tool:", t.name, "| params:", list(t.params_json_schema["properties"]))
