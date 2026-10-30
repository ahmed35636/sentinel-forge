"""The investigation client communicates with a real MCP subprocess."""

import json
import sys
from datetime import timedelta
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .agent import InvestigationAgent


async def run_investigation(
    events: Path, intel: Path | None, host: str, record_id: str, max_calls: int = 32
):
    args = ["-m", "sentinel_forge.server", "--events", str(events.resolve())]
    if intel:
        args += ["--intel", str(intel.resolve())]
    server = StdioServerParameters(command=sys.executable, args=args)
    async with stdio_client(server) as (read, write):
        async with ClientSession(
            read, write, read_timeout_seconds=timedelta(seconds=30)
        ) as session:
            await session.initialize()

            async def call_tool(name, arguments):
                result = await session.call_tool(name, arguments)
                if result.isError:
                    raise RuntimeError(f"MCP tool {name} failed")
                if result.structuredContent is not None:
                    return result.structuredContent
                text = "".join(block.text for block in result.content if block.type == "text")
                return json.loads(text)

            return await InvestigationAgent(call_tool, max_calls).investigate(host, record_id)
