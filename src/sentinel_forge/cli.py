import argparse
import asyncio
import json
from pathlib import Path

from .client import run_investigation
from .report import render_markdown


def main():
    parser = argparse.ArgumentParser(description="Investigate a Windows event through MCP tools")
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--intel", type=Path)
    parser.add_argument("--host", required=True)
    parser.add_argument("--record-id", required=True)
    parser.add_argument("--max-calls", type=int, default=32)
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 2 <= args.max_calls <= 100:
        parser.error("--max-calls must be between 2 and 100")
    case = asyncio.run(
        run_investigation(args.events, args.intel, args.host, args.record_id, args.max_calls)
    )
    output = (
        render_markdown(case) if args.format == "markdown" else json.dumps(case, indent=2) + "\n"
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    if case["status"] == "incomplete":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
