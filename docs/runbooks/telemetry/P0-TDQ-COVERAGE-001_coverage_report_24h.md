# P0-TDQ-COVERAGE-001 — Coverage report (last 24h)

## Objective
Generate an auditable 24h coverage report for the home SOC telemetry using Wazuh Indexer data.

## Data source
- Indexer: OpenSearch/Wazuh Indexer
- Index pattern: `wazuh-archives-4.x-*`
- Time window: `now-24h .. now`

## Output (auditable evidence)
Standard artifact path:
- `artifacts/telemetry/coverage/coverage_24h_YYYY-MM-DD.md`

## Report contents
- Total events in the last 24h
- Top agents (`agent.name`)
- Top Windows hosts (`data.win.system.computer`)
- Top Windows channels (`data.win.system.channel`)

## How to run (CLI)
Runner script:
- `tools/telemetry/coverage_report_24h.sh`

Command (copy/paste):
- `cd ~/soc-cases && tools/telemetry/coverage_report_24h.sh`

## Expected output (example)
- `OK: wrote /home/socadmin/soc-cases/artifacts/telemetry/coverage/coverage_24h_YYYY-MM-DD.md`
- `OK: coverage report generated (no secrets printed)`

## PASS/FAIL criteria
- **PASS**: report file is generated successfully and contains `**PASS** (report generated).`
- **FAIL**: runner exits non-zero (e.g., missing indexer credentials or indexer HTTP != 200).

## Security / secrets
- Credentials are loaded from `~/.secrets/mini-soc.env` (`WAZUH_INDEXER_USER/WAZUH_INDEXER_PASS`).
- Secrets are never printed in terminal output or committed artifacts.

## Notes
- The runner does not depend on the current working directory (it resolves repo root from script path).
- Scheduling (timer/cron) is optional and out of scope for closing this P0 check.
