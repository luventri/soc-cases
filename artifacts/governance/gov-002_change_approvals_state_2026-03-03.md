# GOV-002 Change approvals state (2026-03-03T11:29:01+00:00)

## Policy reference
- docs/governance/change-control.md

## Branch protection review settings (main)
```json
{"url":"https://api.github.com/repos/luventri/SOC/branches/main/protection/required_pull_request_reviews","dismiss_stale_reviews":true,"require_code_owner_reviews":true,"require_last_push_approval":false,"required_approving_review_count":1}
```

## Branch protection required checks (main)
```text
Secret scanning (gitleaks) / gitleaks (pull_request)
Security policy checks / policy (pull_request)
Lint and audit controls / lint-audit (pull_request)
```

## GOV-002 validation summary
- Risk tiers documented (low/medium/high): YES
- Reviewer requirements by risk tier documented: YES
- Rollback expectations documented: YES
- Release notes + evidence linkage documented: YES
- Branch protection minimum approvals configured: YES (required_approving_review_count=1)
