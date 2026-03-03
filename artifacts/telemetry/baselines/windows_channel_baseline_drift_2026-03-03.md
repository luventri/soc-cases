# Windows channel baseline + drift

- Reference date (UTC): 2026-03-03
- Window (UTC): 2026-02-17 .. 2026-03-03
- Latest coverage artifact used: 2026-02-27
- Coverage reports in window: 1
- Drift threshold: +/-40% (for channels with baseline mean >= 50)
- Minimum baseline samples required: 3

## Channel drift table

| Channel | Latest | Baseline mean | Baseline median | Samples | Drift % | Status | Action |
|---|---:|---:|---:|---:|---:|---|---|
| Security | 5995 | 0.0 | 0.0 | 0 | 100.0 | WARN | Collect more daily coverage reports to stabilize baseline |
| Microsoft-Windows-Sysmon/Operational | 2587 | 0.0 | 0.0 | 0 | 100.0 | WARN | Collect more daily coverage reports to stabilize baseline |
| System | 119 | 0.0 | 0.0 | 0 | 100.0 | WARN | Collect more daily coverage reports to stabilize baseline |
| Application | 94 | 0.0 | 0.0 | 0 | 100.0 | WARN | Collect more daily coverage reports to stabilize baseline |

## Result

**WARN** - Baseline exists but sample size is still limited for at least one channel.
