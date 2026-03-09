# OLA1-NET-003 — pfSense Network DQ Gate

## Objective
Validate that pfSense network telemetry remains healthy with a repeatable pass/fail gate.

## Gate script
- `tools/dq/network_pfsense_gate.sh`

## What it validates
- N1 (MUST): recent ingest from pfSense source IP (`location=192.168.242.131`) in configured window.
- N2 (MUST): `filterlog` events present.
- N3 (MUST): key fields are parseable from filterlog sample (action, proto, src/dst ip, src/dst ports).
- N4 (WARN): auxiliary non-filterlog signal (`dhcpd` or test/system message).

## Usage
```bash
tools/dq/network_pfsense_gate.sh --minutes 15 --source-ip 192.168.242.131
```

Optional:
- `--date YYYY-MM-DD`

## Outputs
- Run log: `artifacts/dq/network/pfsense_gate_run_YYYY-MM-DD.log`
- Gate artifact: `artifacts/dq/network/pfsense_gate_YYYY-MM-DD.md`
- On failure:
  - `artifacts/dq/network/pfsense_gate_fail_YYYY-MM-DD.md`
  - issue creation attempted via `gh` (best effort)

## Exit codes
- `0` -> PASS or PASS_WITH_WARN
- `1` -> FAIL (one or more MUST checks failed)
- `2` -> configuration/runtime error

## Operational notes
- Requires `~/.secrets/mini-soc.env` with indexer credentials.
- Uses `wazuh-archives-4.x-*` by default (overridable via env).
- Keep Wazuh manager syslog allowlist constrained to pfSense source IP.
