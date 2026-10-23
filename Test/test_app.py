
import asyncio

import app


def test_process_incident_rejects_empty_incident_id():
    result = asyncio.run(
        app.process_incident(
            "",
            "The VPN keeps disconnecting and I cannot access the network.",
            "VPN",
        )
    )

    assert "Missing information" in result[0]


def test_process_incident_calls_orchestration(monkeypatch):
    called = {}

    class FakeResult:
        incident_id = "INC-TEST-001"
        route = "human_review"
        suggested_workers = []
        message = "Human review is required."
        human_review_required = True
        triage = {"category": "vpn"}
        investigation = None

    async def fake_orchestrate_incident(incident):
        called["incident"] = incident
        return FakeResult()

    monkeypatch.setattr(
        app,
        "orchestrate_incident",
        fake_orchestrate_incident,
    )

    result = asyncio.run(
        app.process_incident(
            "INC-TEST-001",
            "The VPN keeps disconnecting and I cannot access the network.",
            "VPN",
        )
    )

    assert "incident" in called
    assert called["incident"].incident_id == "INC-TEST-001"
    assert "Human review required" in result[0]
    assert result[1] == {"category": "vpn"}
    assert result[2] is None


def test_process_incident_handles_orchestration_error(monkeypatch):
    async def fake_orchestrate_incident(incident):
        raise RuntimeError("Simulated test error")

    monkeypatch.setattr(
        app,
        "orchestrate_incident",
        fake_orchestrate_incident,
    )

    result = asyncio.run(
        app.process_incident(
            "INC-TEST-002",
            "The VPN keeps disconnecting and I cannot access the network.",
            "VPN",
        )
    )

    assert "Processing error" in result[0]
