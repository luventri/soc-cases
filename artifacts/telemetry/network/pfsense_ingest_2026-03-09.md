# OLA1-NET-002 Evidence — pfSense telemetry ingest (2026-03-09)

## Scope
- Source: `soc-fw` (pfSense CE 2.8.1)
- Source IP: `192.168.242.131`
- Destination: `192.168.242.128:514/udp` (Wazuh manager)
- Target index: `wazuh-archives-4.x-*`

## Technical changes applied
1. Wazuh manager syslog listener enabled in `wazuh_manager.conf`:
   - `<connection>syslog</connection>`
   - `<port>514</port>`
   - `<protocol>udp</protocol>`
   - `<allowed-ips>192.168.242.131</allowed-ips>`
2. Manager container recreated to apply config.
3. pfSense remote logging configured to `192.168.242.128:514` with:
   - Firewall Events
   - System Events
   - DHCP Events

## Validation evidence

### A) Wire-level send from pfSense (tcpdump)
Observed on pfSense WAN (`em0`):
- `192.168.242.131.514 > 192.168.242.128.514: SYSLOG kernel.info`
- `192.168.242.131.<ephemeral> > 192.168.242.128.514: SYSLOG user.notice`

Conclusion: pfSense emits syslog UDP/514 toward Wazuh manager.

### B) Direct logger test ingested in Wazuh
Manager archives entry found in `/var/ossec/logs/archives/archives.json`:

- `hostname: soc-fw`
- `program_name: pfsense-test`
- `location: 192.168.242.131`
- `full_log: Mar 9 16:28:20 soc-fw pfsense-test: OLA1-NET-002 direct logger test`

Conclusion: syslog path pfSense -> Wazuh manager -> archives is operational.

### C) Real firewall telemetry in Indexer
Indexer query (`now-15m`) returned multiple records with:
- `location: 192.168.242.131`
- `full_log` containing `filterlog[...]`
- examples of pass events on LAN traffic (DNS/UDP flows to `192.168.114.254:53`)

Conclusion: production-like pfSense firewall logs are ingested and searchable.

## Result
**PASS** — `OLA1-NET-002` validated.

- pfSense logs are exported to SIEM.
- Basic parsing/searchability is confirmed (`location` + `full_log` content).

## Residual notes
1. Current parsing is baseline (syslog + `full_log` string matching); structured field extraction can be improved in `OLA1-NET-003`.
2. Existing unrelated manager warning persists:
   - `wazuh-remoted: Cannot create multigroup directory ... Permission denied`
   - tracked separately (does not block pfSense syslog ingest).
