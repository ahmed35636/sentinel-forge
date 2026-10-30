# SentinelForge investigation

Host: LAB-WS01  
Seed record: 2  
Priority: **P1** (score 100/100)  
Status: completed

Collected 8 events and 5 detection leads.

## Detection leads

| Record | Finding | ATT&CK | Reason |
|---|---|---|---|
| 2 | Encoded PowerShell command | T1059.001 | Encoded command flag in PowerShell telemetry |
| 8 | PsExec process observed | T1569.002 | PsExec binary or service observed; verify remote-service context |
| 7 | Scheduled task creation | T1053.005 | Task creation event or schtasks /create command |
| 4 | PowerShell network retrieval | T1059.001 | Network retrieval primitive in PowerShell telemetry |
| 6 | LSASS memory-read access | T1003.001 | Process access to LSASS with VM_READ (mask 0x1010) |

## Limitations

- Snapshot-only evidence; findings require analyst validation and do not prove compromise.

## Next steps

- Validate the process lineage and user authorization.
- Compare the observed behavior with the host baseline.
- Preserve relevant logs and escalate confirmed suspicious activity through the response playbook.

## Evidence timeline

| Record | Time | Event ID | Image / source |
|---|---|---|---|
| 1 | 2026-10-01T09:00:01Z | 1 | C:\Windows\System32\cmd.exe |
| 2 | 2026-10-01T09:00:02Z | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| 3 | 2026-10-01T09:00:03Z | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| 4 | 2026-10-01T09:00:04Z | 4104 | — |
| 5 | 2026-10-01T09:00:05Z | 1 | C:\Lab\reader.exe |
| 6 | 2026-10-01T09:00:06Z | 10 | C:\Lab\reader.exe |
| 7 | 2026-10-01T09:00:07Z | 1 | C:\Windows\System32\schtasks.exe |
| 8 | 2026-10-01T09:00:08Z | 1 | C:\Lab\PsExec.exe |

## Tool trace

1. **get_event** — {"host": "LAB-WS01", "record_id": "2"}
2. **process_tree** — {"host": "LAB-WS01", "process": "{ps}"}
3. **network_activity** — {"host": "LAB-WS01", "process": "{ps}"}
4. **network_activity** — {"host": "LAB-WS01", "process": "{reader}"}
5. **network_activity** — {"host": "LAB-WS01", "process": "{remote}"}
6. **network_activity** — {"host": "LAB-WS01", "process": "{root}"}
7. **network_activity** — {"host": "LAB-WS01", "process": "{task}"}
8. **powershell_activity** — {"host": "LAB-WS01", "processes": ["{ps}", "{reader}", "{remote}", "{root}", "{task}"]}
9. **lsass_access** — {"host": "LAB-WS01", "processes": ["{ps}", "{reader}", "{remote}", "{root}", "{task}"]}
10. **psexec_activity** — {"host": "LAB-WS01", "processes": ["{ps}", "{reader}", "{remote}", "{root}", "{task}"]}
11. **scheduled_tasks** — {"host": "LAB-WS01", "processes": ["{ps}", "{reader}", "{remote}", "{root}", "{task}"]}
12. **threat_intelligence** — {"indicator": "203.0.113.42"}
