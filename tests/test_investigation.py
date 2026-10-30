import asyncio
from pathlib import Path

import pytest

from sentinel_forge.agent import InvestigationAgent
from sentinel_forge.client import run_investigation
from sentinel_forge.detections import detect
from sentinel_forge.events import Event
from sentinel_forge.server import create_server
from sentinel_forge.store import TelemetryStore

DATA = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture
def store():
    return TelemetryStore(DATA / "events.jsonl", DATA / "intel.json")


def test_host_and_guid_scoping(store):
    assert store.query_events("OTHER")["total"] == 0
    assert store.network_activity("LAB-WS01", "{ps}")["events"][0]["record_id"] == "3"
    assert store.network_activity("LAB-WS01", "{reader}")["total"] == 0
    with pytest.raises(ValueError):
        store.get_event("OTHER", "2")


def test_query_bounds(store):
    result = store.query_events("LAB-WS01", limit=1)
    assert result["truncated"] and result["total"] == 10
    with pytest.raises(ValueError):
        store.query_events("LAB-WS01", limit=10000)


def test_tree_and_cycle_guard(store):
    result = store.process_tree("LAB-WS01", "{ps}")
    assert {e["record_id"] for e in result["events"]} == {"1", "2", "5", "7", "8"}
    assert store.process_tree("LAB-WS01", "{ps}", max_nodes=2)["truncated"]
    store.events = [
        Event("1", 1, "h", "", {"ProcessGuid": "a", "ParentProcessGuid": "b"}),
        Event("2", 1, "h", "", {"ProcessGuid": "b", "ParentProcessGuid": "a"}),
    ]
    assert len(store.process_tree("h", "a")["events"]) == 2


def test_lsass_access_masks():
    for mask, expected in [("0x1010", True), ("0x1000", False), ("garbage", False)]:
        event = Event(
            "1",
            10,
            "h",
            "",
            {"TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": mask},
        )
        assert bool(detect(event)) == expected


def test_intel_exact_match(store):
    assert store.threat_intelligence("203.0.113.42")["matched"]
    assert not store.threat_intelligence("192.0.2.10")["matched"]
    with pytest.raises(ValueError):
        store.threat_intelligence("https://example.invalid")


def test_budget_reports_incomplete(store):
    async def call(name, args):
        return getattr(store, name)(**args)

    result = asyncio.run(InvestigationAgent(call, max_calls=2).investigate("LAB-WS01", "2"))
    assert len(result["tool_trace"]) == 2
    assert result["status"] == "incomplete"
    assert any("budget" in line.lower() for line in result["limitations"])


def test_missing_guid_is_not_overclaimed(store):
    store.events.append(Event("100", 1, "LAB-WS01", "", {}))

    async def call(name, args):
        return getattr(store, name)(**args)

    result = asyncio.run(InvestigationAgent(call).investigate("LAB-WS01", "100"))
    assert result["status"] == "incomplete"
    assert len(result["tool_trace"]) == 1


def test_mcp_registration(store):
    names = {tool.name for tool in asyncio.run(create_server(store).list_tools())}
    assert names == {
        "get_event",
        "query_events",
        "process_tree",
        "network_activity",
        "powershell_activity",
        "lsass_access",
        "psexec_activity",
        "scheduled_tasks",
        "threat_intelligence",
    }


def test_real_stdio_round_trip():
    case = asyncio.run(
        run_investigation(DATA / "events.jsonl", DATA / "intel.json", "LAB-WS01", "2")
    )
    assert case["status"] == "completed"
    assert case["priority"] == "P1"
    assert {e["record_id"] for e in case["evidence"]} == {str(i) for i in range(1, 9)}
    assert len(case["tool_trace"]) == 12
    assert {f["technique"] for f in case["findings"]} == {
        "T1059.001",
        "T1003.001",
        "T1569.002",
        "T1053.005",
    }
    assert case["intelligence"][0]["matched"]
    assert "9" not in {e["record_id"] for e in case["evidence"]}


def test_cross_host_tool_output_rejected():
    async def call(name, args):
        if name == "get_event":
            return Event("1", 1, "a", "", {"ProcessGuid": "x"}).to_dict()
        return {"events": [Event("1", 1, "b", "").to_dict()]}

    with pytest.raises(ValueError, match="another host"):
        asyncio.run(InvestigationAgent(call).investigate("a", "1"))
