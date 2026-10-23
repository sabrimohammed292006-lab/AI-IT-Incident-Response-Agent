"""Execution context for the AI IT Incident Response Agent."""

from __future__ import annotations

import json
from typing import Any


class IncidentContext:
    """Context holding request metadata, user ID, and tool execution history."""

    def __init__(
        self,
        requester_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        self.requester_id = requester_id
        self.session_id = session_id
        self.tool_results: list[dict[str, Any]] = []
        self.tool_log: list[dict[str, Any]] = []

    @property
    def called_tools(self) -> set[str]:
        """Return a set of all successfully executed tools, completely excluding unauthorized/failed calls."""
        tools = set()
        # Check tool_results
        for item in self.tool_results:
            name = item.get("tool_name")
            if name and name != "unknown":
                res = item.get("result")
                if isinstance(res, dict):
                    err = res.get("error")
                    if err or "UNAUTHORIZED" in str(res):
                        continue
                tools.add(name)

        # Check tool_log for any errors/unauthorized entries
        for log in self.tool_log:
            if isinstance(log, dict):
                if log.get("error") or "UNAUTHORIZED" in str(log):
                    name = log.get("tool_name")
                    if name in tools:
                        tools.remove(name)

        return tools

    def record_tool_result(
        self,
        tool_name: str,
        args: dict[str, Any],
        result: Any,
    ) -> None:
        self.record(result, tool_name=tool_name, args=args)

    def record(
        self,
        result: Any,
        tool_name: str | None = None,
        args: dict[str, Any] | None = None,
    ) -> None:
        name = tool_name or "unknown"
        parsed_result = result
        if isinstance(result, str):
            try:
                parsed_result = json.loads(result)
            except Exception:
                pass

        entry = {
            "tool_name": name,
            "args": args or {},
            "result": parsed_result,
        }
        self.tool_results.append(entry)

        if isinstance(parsed_result, dict):
            self.tool_log.append(parsed_result)
        else:
            self.tool_log.append({"tool_name": name, "output": parsed_result})
