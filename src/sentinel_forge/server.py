"""Read-only MCP tools. Telemetry paths are set by the operator at startup."""

import argparse

from mcp.server.fastmcp import FastMCP

from .store import TelemetryStore


def create_server(store: TelemetryStore) -> FastMCP:
    mcp = FastMCP("SentinelForge")

    @mcp.tool()
    def get_event(host: str, record_id: str) -> dict:
        """Fetch one event by host and record ID."""
        return store.get_event(host, record_id)

    @mcp.tool()
    def query_events(
        host: str, event_id: int | None = None, process: str | None = None, limit: int = 100
    ) -> dict:
        """Query a bounded slice of the configured snapshot."""
        return store.query_events(host, event_id, process, limit)

    @mcp.tool()
    def process_tree(host: str, process: str, max_nodes: int = 50) -> dict:
        """Resolve the ancestor chain and descendants, within the same host."""
        return store.process_tree(host, process, max_nodes)

    @mcp.tool()
    def network_activity(host: str, process: str) -> dict:
        """Find Sysmon Event ID 3 connections for a process GUID."""
        return store.network_activity(host, process)

    @mcp.tool()
    def powershell_activity(host: str, processes: list[str]) -> dict:
        """Inspect encoded commands and download primitives in PowerShell telemetry."""
        return store.behavior(host, "powershell", processes)

    @mcp.tool()
    def lsass_access(host: str, processes: list[str]) -> dict:
        """Inspect Sysmon 10 access masks for LSASS memory-read leads."""
        return store.behavior(host, "lsass", processes)

    @mcp.tool()
    def psexec_activity(host: str, processes: list[str]) -> dict:
        """Find PsExec process and service evidence."""
        return store.behavior(host, "psexec", processes)

    @mcp.tool()
    def scheduled_tasks(host: str, processes: list[str]) -> dict:
        """Find task creation evidence from schtasks or Security 4698."""
        return store.behavior(host, "scheduled_tasks", processes)

    @mcp.tool()
    def threat_intelligence(indicator: str) -> dict:
        """Check an IP against the operator-supplied local intelligence snapshot."""
        return store.threat_intelligence(indicator)

    return mcp


def main():
    parser = argparse.ArgumentParser(
        description="Serve a read-only telemetry snapshot over MCP stdio"
    )
    parser.add_argument("--events", required=True)
    parser.add_argument("--intel")
    args = parser.parse_args()
    create_server(TelemetryStore(args.events, args.intel)).run(transport="stdio")


if __name__ == "__main__":
    main()
