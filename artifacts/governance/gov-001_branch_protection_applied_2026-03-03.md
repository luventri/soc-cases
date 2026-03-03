# GOV-001 Branch protection applied (2026-03-03T11:11:12+00:00)

## Command used
```bash
gh api --method PUT repos/luventri/SOC/branches/main/protection \
  -H 'Accept: application/vnd.github+json' \
  --input protection.json
```

## Current protection state (main)
```json
{"url":"https://api.github.com/repos/luventri/SOC/branches/main/protection","required_status_checks":{"url":"https://api.github.com/repos/luventri/SOC/branches/main/protection/required_status_checks","strict":true,"contexts":["Secret scanning (gitleaks) / gitleaks (pull_request)","Security policy checks / policy (pull_request)","Lint and audit controls / lint-audit (pull_request)"],"contexts_url":"https://api.github.com/repos/luventri/SOC/branches/main/protection/required_status_checks/contexts","checks":[{"context":"Secret scanning (gitleaks) / gitleaks (pull_request)","app_id":null},{"context":"Security policy checks / policy (pull_request)","app_id":null},{"context":"Lint and audit controls / lint-audit (pull_request)","app_id":null}]},"required_pull_request_reviews":{"url":"https://api.github.com/repos/luventri/SOC/branches/main/protection/required_pull_request_reviews","dismiss_stale_reviews":true,"require_code_owner_reviews":true,"require_last_push_approval":false,"required_approving_review_count":1},"required_signatures":{"url":"https://api.github.com/repos/luventri/SOC/branches/main/protection/required_signatures","enabled":false},"enforce_admins":{"url":"https://api.github.com/repos/luventri/SOC/branches/main/protection/enforce_admins","enabled":true},"required_linear_history":{"enabled":true},"allow_force_pushes":{"enabled":false},"allow_deletions":{"enabled":false},"block_creations":{"enabled":false},"required_conversation_resolution":{"enabled":true},"lock_branch":{"enabled":false},"allow_fork_syncing":{"enabled":false}}```

## Required checks contexts
```text
Secret scanning (gitleaks) / gitleaks (pull_request)
Security policy checks / policy (pull_request)
Lint and audit controls / lint-audit (pull_request)
```
