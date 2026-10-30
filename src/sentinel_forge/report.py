"""Plain Markdown report with evidence references and the complete tool trace."""

import json


def render_markdown(case: dict) -> str:
    # Quote telemetry and escape table delimiters; it is never treated as report markup.
    def safe(value):
        return (
            str(value)
            .replace("|", "\\|")
            .replace("\n", " ")
            .replace("\r", " ")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("`", "'")
        )

    rows = [
        "# SentinelForge investigation",
        "",
        f"Host: {safe(case['host'])}  ",
        f"Seed record: {safe(case['seed_record_id'])}  ",
        f"Priority: **{case['priority']}** (score {case['score']}/100)  ",
        f"Status: {case['status']}",
        "",
        case["summary"],
        "",
        "## Detection leads",
        "",
        "| Record | Finding | ATT&CK | Reason |",
        "|---|---|---|---|",
    ]
    for f in case["findings"]:
        rows.append(
            f"| {safe(f['record_id'])} | {safe(f['title'])} | {f['technique']} | {safe(f['reason'])} |"
        )
    if not case["findings"]:
        rows.append(
            "| — | No configured detection matched | — | Absence of a match is not proof of benign activity |"
        )
    for title, values in [("Limitations", case["limitations"]), ("Next steps", case["next_steps"])]:
        rows += ["", f"## {title}", ""] + [f"- {safe(value)}" for value in values]
    rows += [
        "",
        "## Evidence timeline",
        "",
        "| Record | Time | Event ID | Image / source |",
        "|---|---|---|---|",
    ]
    for e in case["evidence"]:
        rows.append(
            f"| {safe(e['record_id'])} | {safe(e['timestamp'])} | {e['event_id']} | {safe(e['data'].get('Image', e['data'].get('SourceImage', '—')))} |"
        )
    rows += ["", "## Tool trace", ""]
    for step in case["tool_trace"]:
        rows.append(
            f"{step['step']}. **{step['tool']}** — {safe(json.dumps(step['arguments'], sort_keys=True))}"
        )
    return "\n".join(rows) + "\n"
