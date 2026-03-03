# Change Control Policy (GOV-001)

## Scope
This policy defines how changes are proposed, reviewed, and merged in `luventri/SOC` before Wave 1 (`OLA1-*`) starts.

## Standard flow
1. Create branch from `main` using naming convention:
   - `governance/*`, `feature/*`, `fix/*`, `hotfix/*`
2. Implement scoped changes on branch.
3. Open Pull Request (PR) to `main`.
4. Run required checks and gather evidence.
5. Obtain required review(s) according to risk tier.
6. Merge PR after all required checks pass.
7. Keep auditable evidence in `docs/` and `artifacts/` when applicable.

Direct pushes to `main` are prohibited by policy.

## Required checks (must pass)
Current required CI workflows for PRs:
- `Secret scanning (gitleaks)`
- `Security policy checks`
- `Lint and audit controls`

If workflow names change, update this list and branch protection settings in the same PR.

## CODEOWNERS and area responsibilities
Ownership is enforced through `CODEOWNERS` (repo root).

Role mapping (current single-operator home SOC):
- SOC Engineer: `@luventri`
- SOC Manager: `@luventri`
- Documentation/Knowledge Manager: `@luventri`

Minimum ownership coverage:
- `tools/**` -> SOC Engineer
- `docs/**` -> Documentation/Knowledge Manager
- `.github/workflows/**` -> SOC Engineer + SOC Manager
- `artifacts/**` -> no strict owner; still subject to review and secret controls

## Risk-based change policy
All PRs must classify risk (`low|medium|high`) and comply with the approval matrix below.

### Approval matrix (required)

| Risk | Typical scope | Minimum approvals | Role expectation | Mandatory PR contents |
|---|---|---:|---|---|
| Low | Docs-only, comments, non-functional cleanup | 1 | Any code owner | Summary + impacted paths |
| Medium | Script logic, thresholds, runbook command changes | 1 | Area code owner (SOC Engineer preferred) | Validation evidence + rollback note |
| High | Auth/secrets, CI policy/workflows, RBAC, stack behavior | 1 | SOC Manager policy approval + SOC Engineer technical approval (can be same person in home SOC) | Validation evidence + explicit rollback plan + post-change verification evidence |

### Low risk
Examples:
- docs updates
- comments/non-functional formatting
- artifact housekeeping (sanitized)

Requirements:
- 1 reviewer
- required checks pass
- rollback note optional

### Medium risk
Examples:
- detection logic/script changes
- onboarding/ops scripts
- alert thresholds

Requirements:
- 1 reviewer (preferably role-relevant owner)
- required checks pass
- rollback note mandatory in PR body
- evidence of local validation in PR body

### High risk
Examples:
- auth/secrets handling
- CI policy/workflow changes
- access-control/RBAC logic
- production stack behavior changes

Requirements:
- 1+ reviewer (SOC Manager approval required by policy)
- required checks pass
- explicit test evidence + rollback plan mandatory
- post-change verification evidence mandatory

## Rollback expectations
- Every medium/high-risk PR must include:
  - rollback trigger condition
  - rollback steps (exact commands/paths)
  - expected rollback verification
- If rollback is not technically possible, PR must document compensating controls and recovery path.

## Release notes and evidence requirements
- Every merged PR must leave an auditable note in one of:
  - PR description (preferred), or
  - linked governance/runbook update.
- Minimum required metadata:
  - purpose/scope
  - risk tier
  - files changed (high level)
  - validation commands executed
  - evidence artifact paths (if applicable)
- Medium/high-risk changes must include at least one reproducible evidence path under `artifacts/` or explicit rationale if no artifact applies.

## Break-glass (hotfix) procedure
Use only for service restoration or active security incident.

Policy:
1. Apply minimal hotfix on `hotfix/*` branch.
2. Open PR and merge with expedited review (as available).
3. If emergency requires temporary bypass of normal flow, create a mandatory post-mortem PR within 24h.
4. Post-mortem PR must include:
   - incident timeline
   - root cause
   - exact change applied
   - follow-up controls to avoid recurrence

## Codex-specific change rules
1. Codex changes must be scope-limited to explicit task.
2. Codex must not commit directly to `main`.
3. Codex PR must include:
   - summary of changed files
   - validation commands and outputs summary
   - evidence paths (artifacts/docs)
   - manual steps pending (if permissions/API blocked)
4. No secrets in prompts, commits, logs, docs, or artifacts.
5. Respect `~/.secrets/*`, gitleaks checks, and `tools/platform/secrets_audit.sh`.

## Branch protection checklist (manual/apply)
Target branch: `main`

Required settings:
- Disable direct pushes to `main`
- Require pull request before merging
- Require approvals (minimum 1)
- Require status checks before merging
- Block merge if checks fail

GitHub UI path:
1. Repository `Settings`
2. `Branches`
3. `Add rule` (or rulesets equivalent) for `main`
4. Enable the required settings listed above
5. Add required checks:
   - `Secret scanning (gitleaks)`
   - `Security policy checks`
   - `Lint and audit controls`

`gh` CLI reference commands (reproducible evidence):
```bash
gh auth status
gh repo view luventri/SOC
gh api repos/luventri/SOC/branches/main/protection
gh api repos/luventri/SOC/branches/main/protection/required_status_checks --jq '.contexts'
```

## GOV-001 implementation status (this PR)
- Implemented in repo:
  - `docs/governance/change-control.md`
  - `CODEOWNERS`
- Applied:
  - Branch protection for `main` configured via GitHub API with:
    - PR required
    - minimum 1 approval
    - code owner review required
    - required checks enforced
    - admins enforced
    - force-push and deletion disabled

Evidence:
- `artifacts/governance/gov-001_branch_protection_state_YYYY-MM-DD.md`
- `artifacts/governance/gov-001_branch_protection_applied_YYYY-MM-DD.md`
