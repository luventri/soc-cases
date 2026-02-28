# Operational alerts (P1) — 2026-02-28

## Context
- Host running checks: soc-core
- Wazuh manager container: single-node-wazuh.manager-1
- Ingest window: 60m (critical channels)
- Offline window: 60m (any channel)

## Checks (platform host)

### Disk high
- Result:
```text
PASS: disk usage 37% on / (ok < 85%)
```
- Status: PASS (rc=0)

## Discovered agents (from agent_control)

```text
001	LAPTOP-RH48MVJ8	Active
```

## Checks (per agent)

### Agent: 001 / LAPTOP-RH48MVJ8 (Active)

### Ingest down (critical channels)
- Result:
```text
FAIL: index not available today: wazuh-archives-4.x-2026.02.28 (HTTP=404)
```
- Status: FAIL (rc=2)

### Agent offline
- Result:
```text
FAIL: index not available today: wazuh-archives-4.x-2026.02.28 (HTTP=404)
```
- Status: FAIL (rc=2)

## Conclusion
**FAIL** — failures detected:
- ingest:LAPTOP-RH48MVJ8
- agent:LAPTOP-RH48MVJ8
