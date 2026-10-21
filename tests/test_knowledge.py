import json

import pytest

from it_support.data_store import load_json
from it_support.knowledge_tools import KNOWLEDGE_FILE, search_it_knowledge
from it_support.safety import check_action_safety


@pytest.mark.parametrize("query, expected", [
    ("my account is locked", "KB-001"),
    ("password expired cannot login", "KB-002"),
    ("vpn certificate expired", "KB-004"),
    ("vpn timed out", "KB-006"),
    ("laptop is very slow, disk full", "KB-007"),
    ("antivirus disabled suspicious process", "KB-009"),
    ("wifi not working at the office", "KB-010"),
    ("النت فاصل", "KB-010"),
])
def test_finds_the_right_article(query, expected):
    r = search_it_knowledge(query)
    assert r["success"] is True
    assert r["articles"][0]["id"] == expected


def test_category_filter():
    r = search_it_knowledge("vpn", category="vpn")
    assert all(a["category"] == "vpn" for a in r["articles"])


@pytest.mark.parametrize("query", ["my coffee is cold", "can you help me"])
def test_unrelated_query_returns_not_found(query):
    r = search_it_knowledge(query)
    assert r["success"] is False
    assert r["error"]["code"] == "NOT_FOUND"


@pytest.mark.parametrize("query, category", [("", None), ("x" * 301, None), ("vpn", "cooking")])
def test_invalid_input(query, category):
    assert search_it_knowledge(query, category)["error"]["code"] == "INVALID_INPUT"


def test_max_three_results():
    assert len(search_it_knowledge("vpn password expired locked account")["articles"]) <= 3


def test_knowledge_base_steps_are_all_safe():
    """Our own approved fixes must never trip the dangerous-action rules."""
    for article in load_json(KNOWLEDGE_FILE)["articles"]:
        for step in article["steps"]:
            check = check_action_safety(step)
            assert check.allowed, f"{article['id']}: {step} -> {check.violations}"


def test_unexpected_crash_becomes_tool_error(monkeypatch):
    def boom(_):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr("it_support.knowledge_tools.load_json", boom)
    r = search_it_knowledge("vpn")
    assert r["success"] is False
    assert r["error"]["code"] == "TOOL_ERROR"
    json.dumps(r)  # still valid JSON for the Agent
