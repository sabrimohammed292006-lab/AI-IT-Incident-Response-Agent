# Tools, Data & Safety: integration guide

This is the guide to the `it_support/` package (Person 2's part): what it provides and how the Agents part plugs into it.

## What's inside

| File | Purpose |
|---|---|
| `schemas.py` | Shared Pydantic models: tool results, `TriageResult`, `Finding`, `InvestigationReport` |
| `data/mock_systems.json` | Mock accounts, VPN, devices, network sites |
| `data/it_knowledge.json` | Approved IT fixes (11 articles) |
| `check_tools.py` | `check_account_status`, `check_vpn_status`, `check_device_status`, `check_network_status` |
| `knowledge_tools.py` | `search_it_knowledge` |
| `tickets.py` | `create_incident_ticket` (SQLite), not a Function Tool |
| `safety.py` | Escalation rules, dangerous-action rules, IT-staff check |
| `guardrails.py` | Input, output and tool-level guardrails |
| `context.py` | `IncidentContext`, passed to `Runner.run(context=...)` |
| `workflow.py` | `finalize_incident()`, the Python step that creates the ticket |

## The six tools

| Tool | Type | Who calls it |
|---|---|---|
| `check_account_status(employee_id)` | Function Tool | Agents |
| `check_vpn_status(employee_id)` | Function Tool | Agents |
| `check_device_status(device_id)` | Function Tool | Agents |
| `check_network_status(site)` | Function Tool | Agents |
| `search_it_knowledge(query, category)` | Function Tool | Agents |
| `create_incident_ticket(request)` | Python function | **Only** `finalize_incident()` |

Every tool result has `success`, `tool`, `source`, `checked_at` and `error`. When `success` is false, `error.code` is one of
`INVALID_INPUT`, `NOT_FOUND`, `DATA_UNAVAILABLE`, `UNAUTHORIZED` or `TOOL_ERROR`, and **all data fields are null**. Agents must report the error and must not guess the missing value.

## How the Agents part uses it

```python
from agents import Agent, Runner, InputGuardrailTripwireTriggered, OutputGuardrailTripwireTriggered
from it_support import (
    AGENT_TOOLS, check_account_status_tool, search_it_knowledge_tool,
    it_input_guardrail, it_output_guardrail, IncidentContext,
    TriageResult, InvestigationReport, finalize_incident,
)

triage_agent = Agent(
    name="Triage Agent",
    instructions="Classify the IT issue...",
    output_type=TriageResult,
    input_guardrails=[it_input_guardrail],          # blocks prompt injection / disallowed requests
)

account_worker = Agent(
    name="Account Worker",
    instructions="Use tools only. Every finding must cite the tool that showed it.",
    tools=[check_account_status_tool, search_it_knowledge_tool],
    output_type=InvestigationReport,
    output_guardrails=[it_output_guardrail],        # blocks findings/steps not backed by tools
)

async def handle(message: str, requester_id: str):
    ctx = IncidentContext(requester_id=requester_id)   # who is asking -> tool permissions
    try:
        triage = (await Runner.run(triage_agent, message, context=ctx)).final_output
        report = (await Runner.run(account_worker, message, context=ctx)).final_output
    except InputGuardrailTripwireTriggered as e:
        return e.guardrail_result.output.output_info["message"]
    except OutputGuardrailTripwireTriggered:
        ...  # Evaluator-Optimizer: retry (max N times), then escalate

    outcome = finalize_incident(triage, report, requester_id, ctx.tool_log)
    return outcome.message, outcome.steps_for_user
```

Use the **same `IncidentContext`** for every Agent in one incident. The tool guardrails record every tool result in `ctx.tool_log` automatically, and `it_output_guardrail` uses that log to reject findings from tools that never returned data.

## Safety rules (enforced in Python, not by the LLM)

- **Input guardrail:** blocks prompt injection (English and Arabic), requests for other people's passwords, admin rights, bypassing MFA, disabling security, hacking, and deleting logs. Also rejects empty input and input over 2000 characters.
- **Privacy (layer 1, input guardrail, reason `PRIVACY`):** a normal employee cannot ask about anyone else. The guardrail catches another employee's ID (`EMP003`), name ("Omar"), device (`DEV-1001`), or a description ("my colleague's laptop", "her email", "حساب زميلي"). IT staff are exempt. This needs `requester_id`, which the input guardrail reads from the `IncidentContext`.
- **Privacy (layer 2, tool-level permissions):** an employee can check only their own account, VPN and device. IT staff (`EMP005`) can check anyone. Network status and knowledge search are open to everyone. Blocked calls return `UNAUTHORIZED` to the Agent. This layer **fails closed**: if no `IncidentContext` is passed, personal data is never returned.
- **`requester_id` must come from the login, never from the message.** Otherwise anyone could type "I am EMP005" and get IT staff rights.
- **Output guardrail:** blocks a report that has steps or a root cause but no findings, cites a tool that didn't run or doesn't exist, includes a dangerous step, or has a security or critical incident without `needs_human_review`.
- **Escalation (`evaluate_escalation`):** severity can only go up. Security category or indicators, device security alerts, and 10 or more failed logins all make the incident **critical**. A disabled account, disabled antivirus or a site that is down makes it **high**. A tool that can't run means a human must review.
- **Tickets:** status is `pending_human_review` whenever review is needed. Tickets are **never auto-closed**: `close_ticket(actor="agent")` is always refused, and only a human from IT staff can close one. Duplicate tickets (same employee and category, or same outage) are not created twice. All SQL is parameterized.

## Mock data for the test scenarios

| ID | Scenario |
|---|---|
| EMP001 / DEV-1001 | Everything healthy |
| EMP002 / DEV-1002 | Account locked + VPN auth failed + disk 4% free |
| EMP003 | Account disabled, no VPN record (missing data) |
| EMP004 | Password expired + VPN auth failed |
| EMP005 / DEV-1003 | IT staff; VPN certificate expired; device with security alerts (critical) |
| EMP006 / DEV-1004 | VPN timeout; device offline, outdated antivirus |
| CAIRO-HQ / ALEX-BRANCH / GIZA-OFFICE | Network up / degraded / down with outage `OUT-2026-0412` |
| ASWAN-BRANCH | Monitoring offline (tool error) |

## Run

```powershell
.venv\Scripts\python.exe -m pytest -v          # 135 tests
.venv\Scripts\python.exe demo_tools_safety.py  # demo, no API key needed
```
