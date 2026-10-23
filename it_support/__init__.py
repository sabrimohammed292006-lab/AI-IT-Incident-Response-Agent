"""Tools, Data & Safety layer for the AI IT Incident Response Agent.

What the Agents part needs (one import):

    from it_support import (
        AGENT_TOOLS, CHECK_TOOLS, search_it_knowledge_tool,   # Function Tools
        it_input_guardrail, it_output_guardrail,               # Agent guardrails
        IncidentContext,                                       # Runner context
        TriageResult, InvestigationReport, Finding,            # shared output types
        finalize_incident,                                     # Python workflow (creates ticket)
    )
"""

from .check_tools import (
    CHECK_TOOLS,
    check_account_status,
    check_account_status_tool,
    check_device_status,
    check_device_status_tool,
    check_network_status,
    check_network_status_tool,
    check_vpn_status,
    check_vpn_status_tool,
)
from .context import IncidentContext
from .guardrails import (
    check_user_input,
    it_input_guardrail,
    it_output_guardrail,
    validate_report,
)
from .knowledge_tools import search_it_knowledge, search_it_knowledge_tool
from .safety import check_action_safety, evaluate_escalation, is_it_staff
from .schemas import Finding, InvestigationReport, TriageResult
from .tickets import close_ticket, create_incident_ticket, get_ticket, list_tickets
from .workflow import IncidentOutcome, finalize_incident

AGENT_TOOLS = [*CHECK_TOOLS, search_it_knowledge_tool]

__all__ = [
    "AGENT_TOOLS", "CHECK_TOOLS", "IncidentContext", "IncidentOutcome",
    "Finding", "InvestigationReport", "TriageResult",
    "check_account_status", "check_account_status_tool", "check_device_status",
    "check_device_status_tool", "check_network_status", "check_network_status_tool",
    "check_vpn_status", "check_vpn_status_tool", "search_it_knowledge", "search_it_knowledge_tool",
    "check_user_input", "it_input_guardrail", "it_output_guardrail", "validate_report",
    "check_action_safety", "evaluate_escalation", "is_it_staff",
    "create_incident_ticket", "get_ticket", "list_tickets", "close_ticket",
    "finalize_incident",
]
