# OLA1-LNX-002 Manager/Indexer Validation (2026-03-03)

## Manager validation
Command source: `agent_control -l` on `single-node-wazuh.manager-1`

Observed agents:
- `001 LAPTOP-RH48MVJ8 Active`
- `002 soc-linux-endpoint Active`

## Wazuh API validation
Endpoint: `GET /agents?search=soc-linux-endpoint`

Observed fields:
- id: `002`
- name: `soc-linux-endpoint`
- status: `active`
- version: `Wazuh v4.9.2`
- ip: `192.168.242.130`
- lastKeepAlive: recent at validation time

## Indexer validation (archives)
Query window:
- Linux events from `soc-linux-endpoint` in last 60m
- Syscollector/inventory signal in last 6h

Results at validation time:
- Linux events: present
- Syscollector/inventory-related events: present

## Acceptance criteria check
- Agent enrolled and visible: PASS
- Agent active with recent keepalive: PASS
- Events arriving in `wazuh-archives-*`: PASS

## Conclusion
**PASS** — `OLA1-LNX-002` criteria satisfied.
