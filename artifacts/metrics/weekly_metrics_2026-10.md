# Weekly metrics pack 2026-10 (MET-001)

- Generated (UTC): 2026-03-03 14:04 UTC
- Window (UTC): 2026-02-25 .. 2026-03-03
- Sources: artifacts/telemetry/coverage, artifacts/platform/ops-alerts, GitHub Actions

## KPI table

| KPI | Value | Threshold | Status | Action |
|---|---:|---|---|---|
| Coverage evidence days | 1/7 | >=5 reports/week and latest events > 0 | FAIL | Generate missing coverage_24h reports and validate scheduler |
| Ops alerts reliability | runs=5, pass=1, fail=4 | >=5 runs/week and <=1 fail/week | FAIL | Open/track remediation for recurring ops-alerts failures |
| Required CI controls | checked=0, ok=0, fail=0, unknown=0 | gitleaks + policy + lint-audit healthy in last 7d | WARN | Review Actions UI manually and restore gh access for automation |

## Details

### Coverage
- Reports found in window: 1
- Total events sum (available reports): 10000
- Latest coverage artifact date: 2026-02-27
- Latest coverage total events: 10000

### Ops alerts
- Runs found in window: 5
- PASS: 1
- FAIL: 4
- Latest ops-alert artifact date: 2026-03-03
- Latest ops-alert result: FAIL

### CI controls
- Workflows evaluated: Secret scanning (gitleaks), Security policy checks, Lint and audit controls
- Data note: gh unavailable or unauthenticated
- Last-7d summary: checked=0, ok=0, fail=0, unknown=0

## Optional incident metrics
- MTTD: N/A (not instrumented yet)
- MTTR: N/A (not instrumented yet)

## Weekly result
**FAIL** - Weekly baseline not met; prioritize corrective actions before risky merges.
