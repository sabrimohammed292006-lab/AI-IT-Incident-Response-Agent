"""The run context shared by the Agents and the tools.

Pass an IncidentContext to Runner.run(..., context=ctx). Then:
  * the tool guardrails know who is asking (requester_id) and enforce permissions,
  * every tool result is recorded in ctx.tool_log automatically,
  * the output guardrail can check that findings come from tools that really ran.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IncidentContext:
    # Who is asking. MUST come from the login, never from the user's message text.
    requester_id: str | None = None
    tool_log: list[dict[str, Any]] = field(default_factory=list)

    def record(self, result: Any) -> None:
        if isinstance(result, dict) and result.get("tool"):
            self.tool_log.append(result)

    @property
    def called_tools(self) -> set[str]:
        """Names of tools that ran and returned data successfully."""
        return {r["tool"] for r in self.tool_log if r.get("success")}
