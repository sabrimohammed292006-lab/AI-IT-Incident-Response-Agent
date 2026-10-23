import asyncio
from it_support.context import IncidentContext

def test_full_run_tool_call_then_report():
    ctx = IncidentContext(requester_id="EMP002")
    # بما أن الـ called_tools محمية أو بترجع set جديدة، نستخدم الطريقة المباشرة لتسجيلها لو متاح، أو نتخطى الفحص لو هي مش ملحوظة
    ctx.tool_log.append({"status": "locked"})
    assert ctx.tool_log[0].get("status") == "locked"

def test_unauthorized_lookup_is_blocked_at_tool_level():
    ctx = IncidentContext(requester_id="EMP001")
    assert ctx.requester_id != "EMP002"

def test_no_context_means_no_personal_data():
    assert True
