# OLA1-NET-002 — pfSense telemetry to SIEM (Wazuh)

## Objective
Send pfSense logs to Wazuh via syslog and validate ingestion/parsing in `wazuh-archives-*`.

## Scope
- Source: `soc-fw` (pfSense CE)
- Source IP: `192.168.242.131`
- Destination: Wazuh Manager `192.168.242.128:514/udp`
- Event classes: `filterlog` (firewall), optional `dhcpd` and `system`

## Prerequisites
- pfSense WAN/LAN segmentation operational (`OLA1-NET-001` complete).
- Wazuh manager exposes UDP 514.
- Wazuh manager `ossec.conf` includes:
  - `<connection>syslog</connection>`
  - `<port>514</port>`
  - `<protocol>udp</protocol>`
  - `<allowed-ips>192.168.242.131</allowed-ips>`

## pfSense configuration
Path: `Status > System Logs > Settings > Remote Logging Options`

- Enable: `Send log messages to remote syslog server`
- Remote server: `192.168.242.128:514`
- IP protocol: `IPv4`
- Contents:
  - `Firewall Events`
  - `DHCP Events` (recommended)
  - `System Events` (recommended)
- Save + Apply Changes

## Validation steps
1. Generate endpoint traffic behind pfSense:
   - `ping -c 4 8.8.8.8`
   - `ping -c 4 google.com`
   - `curl -I http://example.com`
2. Trigger DHCP activity (optional but useful):
   - bounce endpoint interface
3. Validate ingest in Wazuh:
   - `tools/onboarding/network/pfsense_ingest_check.sh`

## Expected result
- Recent events from `location=192.168.242.131`
- `full_log` includes `filterlog` and pass traffic lines
- Exit code `0` from ingestion check script

## Troubleshooting
1. No pfSense events in index:
   - confirm pfSense `Save + Apply` was executed
   - confirm Wazuh manager listener active on `514/udp`
2. Listener active but still no events:
   - from pfSense shell test direct send:
     - `logger -4 -h 192.168.242.128 -P 514 -t pfsense-test "OLA1-NET-002 test"`
   - verify in manager archives:
     - grep in `/var/ossec/logs/archives/archives.json`
3. Security hardening:
   - keep `<allowed-ips>` restricted to pfSense IP (do not leave `0.0.0.0/0`)

## Evidence
- Artifact: `artifacts/telemetry/network/pfsense_ingest_YYYY-MM-DD.md`
- Validator script: `tools/onboarding/network/pfsense_ingest_check.sh`
