# SOC Hardening Plan (Execution Checklist)

- Baseline date: 2026-02-28 (UTC)
- Scope: `soc-cases` + local customizations in `wazuh-docker/single-node`
- Status key: `TODO` | `IN_PROGRESS` | `DONE` | `BLOCKED`

## 1) Backlog (priority, owner, ETA)

| ID | Priority | Task | Owner | ETA | Status |
|---|---|---|---|---|---|
| H-01 | P0 | Remove hardcoded secrets from custom scripts/config | Platform Eng | 0-1 day | TODO |
| H-02 | P0 | Enforce TLS verification (remove insecure `-k` paths) | Platform Eng | 0-1 day | TODO |
| H-03 | P0 | Fix broken onboarding runbook commands (JSON quoting) | SOC Eng | 0-1 day | TODO |
| H-04 | P0 | Rotate potentially exposed credentials | SecOps + Platform Eng | 0-1 day | TODO |
| H-05 | P1 | Fix index date logic to avoid UTC/day-boundary false FAIL | Platform Eng | 1-2 days | TODO |
| H-06 | P1 | Harden RBAC verification assertions/version handling | Platform Eng | 1-2 days | TODO |
| H-07 | P1 | Harden CI policies (pin actions, block insecure patterns) | DevSecOps | 2-3 days | TODO |
| H-08 | P2 | Add continuous lint/audit gates (shell/yaml/secrets) | DevSecOps | 2 days | TODO |

## 2) Execution Checklist

### H-01: Remove hardcoded secrets

- [ ] Replace embedded credentials in `wazuh-docker/single-node/tools/triage/make_issue_auto.py` with env/file-based secrets.
- [ ] Remove plaintext defaults from `wazuh-docker/single-node/docker-compose.yml` and `wazuh-docker/single-node/config/wazuh_dashboard/wazuh.yml`.
- [ ] Confirm no known hardcoded secret patterns remain.

Commands:
```bash
cd /home/socadmin/wazuh-docker
rg -n "SecretPassword|MyS3cr37|admin:SecretPassword|password:\\s*\".+\"" single-node/tools single-node/config single-node/docker-compose.yml
```

Acceptance:
- No hardcoded production-like credentials remain in custom code/config.
- Runtime credentials resolve only from environment or `~/.secrets/*`.

### H-02: Enforce TLS verification

- [ ] Replace `curl -sk`/`-k` in operational scripts with CA-verified requests.
- [ ] Replace Python SSL contexts that set `CERT_NONE`.
- [ ] Validate scripts still pass with proper certificates.

Commands:
```bash
cd /home/socadmin
rg -n "curl\\s+.*-k|curl\\s+.*-sk|CERT_NONE|check_hostname\\s*=\\s*False" soc-cases wazuh-docker/single-node/tools
```

Acceptance:
- No new insecure TLS bypass in SOC-operational paths.
- Health/onboarding/RBAC scripts run successfully with cert verification enabled.

### H-03: Fix onboarding runbook command quality

- [ ] Repair JSON quoting in onboarding command blocks.
- [ ] Replace one-liners with heredoc JSON examples where needed.
- [ ] Validate command snippets by dry-run in lab shell.

Commands:
```bash
cd /home/socadmin/soc-cases
rg -n 'curl -sk -u "\\$\\{WAZUH_INDEXER_USER\\}:\\$\\{WAZUH_INDEXER_PASS\\}"' docs/runbooks/onboarding/windows/onboarding_windows.md
```

Acceptance:
- Copy/paste commands in runbook execute without shell parsing errors.
- Artifacts are still sanitized and auditable.

### H-04: Rotate exposed credentials

- [ ] Rotate `INDEXER_PASSWORD`, `API_PASSWORD`, dashboard/internal users tied to known defaults.
- [ ] Update local secret store (`~/.secrets/mini-soc.env`) with new values.
- [ ] Re-run validation scripts and keep evidence artifacts.

Commands:
```bash
cd /home/socadmin/soc-cases
tools/access-control/verify-users.sh
tools/platform_health.sh
tools/secrets_audit.sh
```

Acceptance:
- Old credentials invalidated.
- Verification scripts report PASS after rotation.

### H-05: Fix index date boundary logic

- [ ] Update checks to query wildcard indices + time range, not only `YYYY.MM.DD`.
- [ ] Validate around UTC boundary (late-night local time test).

Target files:
- `tools/ops-alerts/check_ingest.sh`
- `tools/ops-alerts/check_agent_offline.sh`

Acceptance:
- No false negatives caused by day rollover.

### H-06: Harden RBAC verification

- [ ] Detect OpenSearch Dashboards version dynamically when possible.
- [ ] Add assertion for `wazuh_search HTTP=200` in verify stage.
- [ ] Keep negative tests (`write/security api/savedobject create`) strict.

Target file:
- `tools/access-control/verify-users.sh`

Acceptance:
- Script fails on real privilege regressions and passes on expected RO profile.

### H-07: Harden CI policy

- [ ] Pin GitHub Actions to immutable SHAs where feasible.
- [ ] Add secret scanning and insecure-pattern checks as required PR gates.
- [ ] Block merges on hardcoded credentials or new TLS bypasses.

Commands:
```bash
cd /home/socadmin
rg -n "uses:\\s*[^@]+@v[0-9]+" soc-cases/.github wazuh-docker/.github
```

Acceptance:
- CI enforces security baseline before merge.

### H-08: Continuous lint/audit controls

- [ ] Add/enable `shellcheck` for SOC scripts.
- [ ] Add/enable `yamllint` for workflows/compose.
- [ ] Keep periodic secrets audit evidence in artifacts.

Commands:
```bash
cd /home/socadmin/soc-cases
find tools -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
tools/secrets_audit.sh
```

Acceptance:
- Syntax/lint/security checks run repeatedly and produce auditable outputs.

## 3) Daily Tracking Update Template

Use this block in PR/issue comments:

```text
Date: YYYY-MM-DD
Owner:
Completed: H-__
In progress: H-__
Blocked: H-__ (reason)
Evidence:
- artifacts/.../file1
- artifacts/.../file2
```

