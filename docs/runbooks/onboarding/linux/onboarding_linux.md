# OLA1-LNX-002 — Linux Agent Onboarding (Wazuh)

## Objective
Install and enroll a Linux endpoint agent into Wazuh Manager and verify telemetry ingestion in Indexer/Dashboard.

## Scope
- Endpoint: `soc-linux-endpoint` (Ubuntu 24.04)
- Manager: `192.168.242.128`
- Wazuh version target: aligned with manager (`4.9.2`)

## Prerequisites
- Endpoint has network reachability to manager.
- System time synchronized.
- Privileged user with `sudo`.

## Procedure
1. Pre-check connectivity
- `ping -c 4 192.168.242.128`
- `nc -vz 192.168.242.128 1514 || true`
- `nc -vz 192.168.242.128 1515 || true`
- `nc -vz 192.168.242.128 55000 || true`

2. Install Wazuh APT repository and agent
- `sudo install -d -m 0755 /usr/share/keyrings`
- `curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg`
- `echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list >/dev/null`
- `sudo apt update`
- `sudo apt install -y wazuh-agent`

3. Ensure version compatibility with manager
- If manager is `4.9.2`, align agent version:
- `sudo apt install -y --allow-downgrades wazuh-agent=4.9.2-1`

4. Configure manager in agent config
- Edit `/var/ossec/etc/ossec.conf` and set manager address:
- `<address>192.168.242.128</address>`

5. Enroll and start agent
- `sudo systemctl daemon-reload`
- `sudo /var/ossec/bin/agent-auth -m 192.168.242.128 -A soc-linux-endpoint`
- `sudo systemctl enable --now wazuh-agent`

6. Local verification
- `sudo systemctl status wazuh-agent --no-pager`
- `sudo journalctl -u wazuh-agent --since "15 min ago" --no-pager | tail -n 80`

7. Manager/Indexer verification
- Manager agent list includes endpoint as `Active`.
- Wazuh API reports `status=active` with recent `lastKeepAlive`.
- `wazuh-archives-*` receives events from `soc-linux-endpoint`.

## Troubleshooting
- Version mismatch (`agent > manager`): enroll may fail. Align versions first.
- Invalid or incompatible `ossec.conf` elements: restore from backup and reapply minimal manager settings.
- Duplicate name/key errors: remove stale agent entry or re-enroll with consistent identity.

## Evidence
- `artifacts/onboarding/linux/ola1-lnx-002_install_YYYY-MM-DD.md`
- `artifacts/onboarding/linux/ola1-lnx-002_validation_YYYY-MM-DD.md`

## Next step
Proceed to `OLA1-LNX-003` (Linux DQ gate with pass/fail checks and issue-on-fail behavior).

---

## OLA1-LNX-003 Linux DQ gate

### Gate runner
- `tools/onboarding/linux/linux_onboarding_audit.sh --agent soc-linux-endpoint --date YYYY-MM-DD`

### Checks implemented
- `M1` Agent active (Wazuh API, keepalive freshness)
- `M2` Ingest freshness in `wazuh-archives-*` (last 60m)
- `M3` Linux log signal present (`pam`/`sudo`/`systemd` in last 24h)
- `M4` Identity consistency (expected agent vs API vs latest event vs syscollector hostname)
- `M5` Syscollector data + freshness (Wazuh API)
- `M6` SCA data freshness (Wazuh API)

### Result policy
- MUST checks: `M1..M5`
- `M6` currently allowed as `WARN` while SCA baseline stabilizes.
- Exit code `0`: MUST checks pass (final `PASS` or `PASS_WITH_WARN`).
- Exit code `1`: one or more MUST checks fail (final `FAIL`, issue-on-fail path).

### Artifacts
- `artifacts/onboarding/linux/M1_*.md` ... `M6_*.md`
- `artifacts/onboarding/linux/gate_run_YYYY-MM-DD.log`
- On FAIL: `artifacts/onboarding/linux/gate_fail_YYYY-MM-DD.md`

### Issue on fail
- Dedupe-safe issue creation script:
  - `tools/onboarding/linux/create_issue_on_fail.sh`
