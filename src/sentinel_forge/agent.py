"""Bounded investigation planner: each next tool call depends on collected evidence."""

from .detections import detect
from .events import normalize
from .store import process_guid


class InvestigationAgent:
    def __init__(self, call_tool, max_calls: int = 32):
        if not 2 <= max_calls <= 100:
            raise ValueError("max_calls must be between 2 and 100")
        self.call_tool = call_tool
        self.max_calls = max_calls

    async def investigate(self, host: str, record_id: str) -> dict:
        trace, evidence, intel, limitations = [], {}, [], []

        async def call(name, **arguments):
            if len(trace) >= self.max_calls:
                if "Tool budget exhausted; investigation is incomplete." not in limitations:
                    limitations.append("Tool budget exhausted; investigation is incomplete.")
                return {}
            result = await self.call_tool(name, arguments)
            trace.append({"step": len(trace) + 1, "tool": name, "arguments": arguments})
            if result.get("truncated"):
                limitations.append(f"{name} returned truncated results.")
            for row in result.get("events", []):
                event = normalize(row)
                if event.host.casefold() != host.casefold():
                    raise ValueError("tool returned evidence for another host")
                evidence[event.record_id] = event
            return result

        raw = await call("get_event", host=host, record_id=record_id)
        seed = normalize(raw)
        if seed.host.casefold() != host.casefold() or seed.record_id != record_id:
            raise ValueError("seed event does not match requested identity")
        evidence[seed.record_id] = seed
        guid = process_guid(seed)
        if guid:
            await call("process_tree", host=host, process=guid)
            processes = sorted({process_guid(e) for e in evidence.values() if process_guid(e)})
            for process in processes:
                await call("network_activity", host=host, process=process)
            # Specialized queries can return events absent from the process-creation tree.
            for tool in (
                "powershell_activity",
                "lsass_access",
                "psexec_activity",
                "scheduled_tasks",
            ):
                await call(tool, host=host, processes=processes)
            ips = sorted(
                {
                    e.value("DestinationIp")
                    for e in evidence.values()
                    if e.event_id == 3 and e.value("DestinationIp")
                }
            )
            for ip in ips:
                try:
                    item = await call("threat_intelligence", indicator=ip)
                    if item:
                        intel.append(item)
                except ValueError:
                    limitations.append(f"Invalid destination IP in evidence: {ip}")
        else:
            limitations.append("Seed lacks a process GUID; process correlation was not attempted.")
        findings = [f.to_dict() for e in evidence.values() for f in detect(e)]
        score = max((f["severity"] for f in findings), default=20)
        if any(
            i.get("matched") and (i.get("intelligence") or {}).get("verdict") == "suspicious"
            for i in intel
        ):
            score = min(100, score + 10)
        priority = "P1" if score >= 85 else "P2" if score >= 60 else "P3"
        limitations.append(
            "Snapshot-only evidence; findings require analyst validation and do not prove compromise."
        )
        return {
            "host": host,
            "seed_record_id": record_id,
            "priority": priority,
            "score": score,
            "status": "incomplete" if len(limitations) > 1 else "completed",
            "summary": f"Collected {len(evidence)} events and {len(findings)} detection leads.",
            "findings": findings,
            "intelligence": intel,
            "evidence": [
                e.to_dict()
                for e in sorted(evidence.values(), key=lambda e: (e.timestamp, e.record_id))
            ],
            "tool_trace": trace,
            "limitations": limitations,
            "next_steps": [
                "Validate the process lineage and user authorization.",
                "Compare the observed behavior with the host baseline.",
                "Preserve relevant logs and escalate confirmed suspicious activity through the response playbook.",
            ],
        }
