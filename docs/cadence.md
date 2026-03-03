# Weekly Operational Cadence (GOV-003)

## Objective
Establish a repeatable weekly governance and operations review ritual for the home SOC, with auditable outputs and clear action ownership.

## Frequency and schedule
- Cadence: weekly
- Recommended day/time: Mondays, 09:00 local (or fixed weekly slot)
- Duration target: 30-45 minutes

## Participants (minimum)
- SOC Manager
- SOC Engineer
- Telemetry Owner

In a single-operator setup, one person can execute all roles, but sections must still be completed explicitly.

## Weekly checklist (required)
1. Platform ops alerts review
   - Source: `artifacts/platform/ops-alerts/ops_alerts_YYYY-MM-DD.md`
   - Check: latest run PASS/FAIL, unresolved recurring failures
   - Action: create/track remediation issues for FAIL items

2. DQ gate and onboarding quality review
   - Source: `artifacts/onboarding/windows/*`, gate fail artifacts/logs (if any)
   - Check: recent gate results and stale FAILs
   - Action: assign owner and ETA for each open DQ gap

3. Backups and restore posture review
   - Source: `artifacts/platform/backup/backup_test_YYYY-MM-DD.md`
   - Check: latest restore test evidence freshness and result
   - Action: schedule next restore test if stale

4. CI/security controls health
   - Source: GitHub Actions runs for:
     - `Secret scanning (gitleaks)`
     - `Security policy checks`
     - `Lint and audit controls`
   - Check: failing workflows, flaky jobs, blocked PRs
   - Action: open remediation issue for persistent failures

5. Open issues triage
   - Source: GitHub Issues labels (`platform`, `ops-alert`, `onboarding`, `telemetry`, `governance`)
   - Check: priority, age, blocker status
   - Action: close stale/no-longer-valid, escalate blocked items

6. Metrics pack status (transition to MET-001)
   - Source: coverage + ops-alerts + CI results (until `docs/metrics.md` + weekly metrics script exist)
   - Check: whether weekly pack inputs are complete
   - Action: track MET-001 progress as priority backlog item

## GO / NO-GO criteria for planned changes
Use this decision gate before approving weekly high-impact changes:

GO if all are true:
- Required CI checks are healthy for active PRs
- No unresolved high-risk platform incident from previous week
- Backup/restore evidence is current (or explicit exception approved)
- Change has risk tier + rollback plan documented

NO-GO if any are true:
- Active incident without containment
- CI required checks are persistently failing without owner
- No recent backup/restore confidence and planned change is high risk

## Weekly evidence artifact
Create one weekly governance artifact:
- `artifacts/governance/weekly_review_YYYY-WW.md`

Minimum contents:
- Meeting date/time
- Participants
- Checklist status per section (PASS/FAIL/NA)
- Open risks/blockers
- Decisions taken
- Actions (owner + ETA)

## Template (copy/paste)
```text
# Weekly Review YYYY-WW
Date:
Participants:

## Checklist
- Ops alerts:
- DQ gate:
- Backups/restore:
- CI/security:
- Open issues:
- Metrics pack status:

## Risks / blockers
- ...

## Decisions
- ...

## Actions
- [ ] Action / Owner / ETA
```

## Implementation status
- GOV-003 policy document established.
- Next step is operational adoption (first 2-3 weekly cycles with artifacts).
