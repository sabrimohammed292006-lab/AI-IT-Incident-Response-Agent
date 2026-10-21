"""The run context shared by the Agents and the tools.

Pass an IncidentContext to Runner.run(..., context=ctx). Then:
    * the tool guardrails know who is asking (requester_id) and enforce permissions,
    * every tool result is recorded in ctx.tool_log automatically,
    * the output guardrail can check that findings come from tools that really ran.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class IncidentContext:
    # Who is asking. MUST come from the login, never from the user's message text.
    requester_id: str | None = None

    tool_log: list[dict[str, Any]] = field(default_factory=list)

    def record(
        self,
        result: Any,
        tool_name: str | None = None,
    ) -> None:
        """Record a tool result together with the actual tool name."""

        if isinstance(result, str):
            try:
                result = json.loads(result)
            except (json.JSONDecodeError, TypeError):
                result = {"result": result}

        if not isinstance(result, dict):
            result = {"result": str(result)}

        recorded = dict(result)

        # The actual tool name comes from the Agents SDK context,
        # not from the tool's returned data.
        if tool_name:
            recorded["tool"] = tool_name

        if recorded.get("tool"):
            self.tool_log.append(recorded)

    @property
    def called_tools(self) -> set[str]:
        """Names of tools that ran and returned data successfully."""

        return {
            record["tool"]
            for record in self.tool_log
            if record.get("success") and record.get("tool")
        }