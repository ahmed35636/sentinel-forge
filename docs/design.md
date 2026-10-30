# Design decisions

## Evidence first

The planner starts with one host-scoped seed. If it has a process GUID, it asks for
that process's ancestors and descendants, then checks those GUIDs for network and
behavior events. Intelligence requests use only observed destination IPs. This
makes each transition inspectable and avoids free-form queries generated from
untrusted command lines. The current planner is a policy agent, not an LLM agent.

## Correlation scope

The tree walks to the oldest available ancestor and includes its descendants.
This can bring in siblings, which are context rather than attribution. GUIDs are
scoped by host. Parent cycles are guarded against. There is no PID inference or
time-window correlation. Missing parent creation events and truncated results
reduce context and are reflected in report limitations where observable.

## Bounded, read-only tools

Paths are supplied at server startup, never through a model tool argument.
Queries cannot run shell commands or fetch arbitrary URLs. Event queries cap at
500 rows; trees cap at 200 nodes. The agent defaults to 32 calls, with an explicit
incomplete state if it runs out. Host mismatches in returned evidence are rejected.
A real MCP stdio transport keeps server and client concerns separate; an in-process
store is used only by focused unit tests. Server logging goes to stderr.

## Report provenance

Each detection cites a record ID. The full JSON case includes normalized evidence,
intelligence source metadata, and ordered tool-call arguments. Markdown is a compact
view of that case. Findings are recomputed from collected evidence, so prose does
not introduce extra observations. Intelligence is a static local lookup: source
and date are retained, but expiration is not enforced. Stale-feed policies would
need to be defined before operational use.

## Storage and scaling

This implementation loads a small JSON/JSONL snapshot into memory and scans it for
queries. It favors easy reproduction over throughput. The store interface is the
replacement boundary for an indexed backend. Process windows, multi-channel IDs,
streaming ingestion, and per-investigator access control are future deployment
requirements rather than implied features.
