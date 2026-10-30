"""Host-scoped queries over a fixed telemetry snapshot."""

import ipaddress
import json
from collections import deque
from pathlib import Path

from .detections import detect
from .events import load_events


def process_guid(event):
    return (
        event.value("ProcessGuid")
        or event.value("SourceProcessGUID")
        or event.value("SourceProcessGuid")
    )


class TelemetryStore:
    def __init__(self, events_path: str | Path, intel_path: str | Path | None = None):
        self.events = load_events(events_path)
        self.intel = json.loads(Path(intel_path).read_text()) if intel_path else {}
        if not isinstance(self.intel, dict):
            raise ValueError("intel must be a JSON object keyed by indicator")

    def scoped(self, host: str):
        if not host.strip():
            raise ValueError("host is required")
        return [e for e in self.events if e.host.casefold() == host.casefold()]

    def get_event(self, host: str, record_id: str) -> dict:
        matches = [e for e in self.scoped(host) if e.record_id == record_id]
        if not matches:
            raise ValueError("record not found on requested host")
        return matches[0].to_dict()

    def query_events(
        self, host: str, event_id: int | None = None, process: str | None = None, limit: int = 100
    ) -> dict:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        rows = [
            e.to_dict()
            for e in self.scoped(host)
            if (event_id is None or e.event_id == event_id)
            and (process is None or process_guid(e) == process)
        ]
        return {"events": rows[:limit], "total": len(rows), "truncated": len(rows) > limit}

    def process_tree(self, host: str, process: str, max_nodes: int = 50) -> dict:
        if not process or not 1 <= max_nodes <= 200:
            raise ValueError("process is required; max_nodes must be between 1 and 200")
        creations = {
            process_guid(e): e for e in self.scoped(host) if e.event_id == 1 and process_guid(e)
        }
        # Walk ancestors first, guarding against corrupt/cyclic parent chains.
        root, seen = process, set()
        while root in creations and root not in seen:
            seen.add(root)
            parent = creations[root].value("ParentProcessGuid")
            if not parent or parent not in creations or parent in seen:
                break
            root = parent
        queue, visited, rows = deque([root]), set(), []
        while queue and len(rows) < max_nodes:
            guid = queue.popleft()
            if guid in visited:
                continue
            visited.add(guid)
            if guid in creations:
                rows.append(creations[guid].to_dict())
            queue.extend(
                g
                for g, event in creations.items()
                if event.value("ParentProcessGuid") == guid and g not in visited
            )
        return {"events": rows, "truncated": bool(queue), "requested_process": process}

    def network_activity(self, host: str, process: str) -> dict:
        return self.query_events(host, event_id=3, process=process)

    def behavior(self, host: str, category: str, processes: list[str]) -> dict:
        categories = {
            "powershell": {"PS_ENCODED", "PS_DOWNLOAD"},
            "lsass": {"LSASS_READ"},
            "psexec": {"PSEXEC"},
            "scheduled_tasks": {"SCHEDULED_TASK"},
        }
        if category not in categories or len(processes) > 200:
            raise ValueError("invalid category or too many processes")
        findings, events = [], []
        for event in self.scoped(host):
            if process_guid(event) not in processes:
                continue
            matches = [f.to_dict() for f in detect(event) if f.rule_id in categories[category]]
            if matches:
                findings.extend(matches)
                events.append(event.to_dict())
        return {
            "events": events[:100],
            "findings": findings[:100],
            "truncated": len(events) > 100 or len(findings) > 100,
        }

    def threat_intelligence(self, indicator: str) -> dict:
        # Exact matches only; no arbitrary URLs, downloads, or shell commands.
        ipaddress.ip_address(indicator)
        match = self.intel.get(indicator)
        return {
            "indicator": indicator,
            "matched": match is not None,
            "intelligence": match,
            "note": "No match means no local evidence, not a benign verdict.",
        }
