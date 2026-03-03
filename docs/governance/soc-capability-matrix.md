# SOC Capability Matrix (Home SOC)

> Status values: TODO | PARTIAL | DONE  
> Priorities: P0 (blocker) | P1 (important) | P2 (nice-to-have)  
> Evidence must be auditable: committed docs/scripts and/or artifacts/logs in repo, sanitized (no secrets).

---

## Base Platform (Core SOC on soc-core)

### BASE-PLAT (Platform Health, Backups, Secrets, Access, Ops Alerts)

| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| BASE-PLAT-001 | Platform | SIEM operational | Wazuh single-node Docker stable | P0 | SOC Engineer | DONE | tools/platform_health.sh; artifacts/platform/health/platform_health_YYYY-MM-DD.md; docs/runbooks/platform/P0-PLAT-HEALTH-001_platform_health_check.md | Health runner produces daily evidence; dashboard reachable; indexer cluster health OK; no secrets exposed | Keep as daily routine |
| BASE-PLAT-002 | Platform | Stack operations | Health checks of stack | P0 | SOC Engineer | DONE | tools/platform_health.sh; artifacts/platform/health/; docs/runbooks/platform/P0-PLAT-HEALTH-001_platform_health_check.md | Repeatable operational health check exists and is documented with evidence | None |
| BASE-PLAT-003 | Platform | Retention & backups | Retention + backup plan | P1 | SOC Engineer | DONE | docs/runbooks/platform/P1-PLAT-BACKUP-001_retention_backup_plan.md; tools/backup/backup_run.sh; tools/backup/backup_restore_test.sh; tools/backup/backup_restore_apply.sh; artifacts/platform/backup/backup_test_YYYY-MM-DD.md | Backup + restore test verified with evidence; secrets excluded; DR apply script guarded | Add periodic DR test cadence (see GOV/MET) |
| BASE-PLAT-004 | Platform | Access control | Minimal accounts/roles | P1 | SOC Manager + SOC Engineer | DONE | docs/governance/access-control.md; tools/access-control/create-analyst-user.sh; tools/access-control/verify-users.sh; artifacts/platform/access-control/*.log | Admin/Engineer and Analyst roles operational; negative tests deny admin APIs/writes; evidence committed | Review after upgrades; keep verify-users in routine |
| BASE-PLAT-005 | Platform | Secrets management | Tokens out of repo | P0 | SOC Engineer | DONE | docs/governance/secrets-management.md; tools/platform/secrets_audit.sh; .github/workflows/secret-scanning-gitleaks.yml; artifacts/platform/secrets/secrets_audit_YYYY-MM-DD.md | Secrets stored outside repo; CI scanning + local audit PASS; .gitignore hardened | Periodic scheduled audit in CI |
| BASE-PLAT-006 | Platform | Internal observability | SOC operational alerts | P1 | SOC Engineer | DONE | docs/runbooks/platform/P1-PLAT-OPS-ALERTS-001_operational_alerts.md; tools/ops-alerts/run_ops_alerts.sh; tools/ops-alerts/systemd/*; artifacts/platform/ops-alerts/ops_alerts_YYYY-MM-DD.md | Ingest down / disk high / agent offline checks exist, notify via Issues, scheduled via systemd, with PASS + simulated FAIL evidence | Add housekeeping for ops artifacts |

---

## Telemetry & Data Quality (Windows baseline + gates)

### BASE-TDQ (Windows onboarding + coverage + DQ gate)

| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| BASE-TDQ-001 | Telemetry/DQ | Onboarding endpoint | Windows onboarding checklist + gates | P0 | Doc/Know + Telemetry Owner | DONE | docs/runbooks/onboarding/windows/onboarding_windows.md; tools/onboarding/windows/windows_onboarding_audit.sh; artifacts/onboarding/windows/M1..M6_*.md | Onboarding is documented and executable; gate returns exit code; artifacts sanitized and reproducible | Extend pattern to Linux in Ola 1 |
| BASE-TDQ-002 | Telemetry/DQ | Base coverage | Windows channels arrive | P0 | Telemetry Owner | DONE | artifacts/onboarding/windows/M2_security_*.md; artifacts/onboarding/windows/M3_sysmon_*.md | Security + Sysmon present within freshness threshold | None |
| BASE-TDQ-003 | Telemetry/DQ | Telemetry modules | syscollector/SCA present | P0 | Telemetry Owner | DONE | artifacts/onboarding/windows/M5_syscollector_*.md; artifacts/onboarding/windows/M6_sca_*.md | syscollector + SCA present with freshness | None |
| BASE-TDQ-004 | Telemetry/DQ | Coverage report | 24h coverage report in artifacts | P0 | SOC Engineer | DONE | tools/telemetry/coverage_report_24h.sh; docs/runbooks/telemetry/P0-TDQ-COVERAGE-001_coverage_report_24h.md; artifacts/telemetry/coverage/coverage_24h_YYYY-MM-DD.md | Runner generates 24h report with stable path; documented; no secrets | Add weekly metrics pack (MET) |
| BASE-TDQ-005 | Telemetry/DQ | Gate DQ v1 | Basic DQ gate (channels+modules) + issue on fail | P0 | SOC Engineer | DONE | tools/onboarding/windows/windows_onboarding_audit.sh; tools/onboarding/windows/create_issue_on_fail.sh; artifacts/onboarding/windows/gate_fail_*.md; artifacts/onboarding/windows/gate_run_FAIL_*.log | Gate produces PASS/FAIL; creates Issue with labels; anti-spam | Add generalized DQ gates for Linux + network sources |

---

## Governance & Operations (to operate like a real SOC)

### GOV (Change control, approvals, cadence)

| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| GOV-001 | Governance | Change control | PR discipline + protections (Codex-safe) | P0 | SOC Manager + SOC Engineer | DONE | docs/governance/change-control.md; CODEOWNERS; artifacts/governance/gov-001_branch_protection_applied_YYYY-MM-DD.md | No direct push to main; PR required; required CI checks; CODEOWNERS enforced; emergency process documented | Keep checks list synchronized with workflows |
| GOV-002 | Governance | Change approvals | Risk tiers for changes | P1 | SOC Manager | DONE | docs/governance/change-control.md; artifacts/governance/gov-002_change_approvals_state_YYYY-MM-DD.md | Define low/med/high-risk changes and required reviewers; rollback expectations | Keep reviewer matrix aligned with branch protection and CODEOWNERS |
| GOV-003 | Governance | Operational cadence | Weekly review ritual | P1 | SOC Manager | DONE | docs/cadence.md; artifacts/governance/weekly_review_YYYY-WW.md | Weekly checklist includes: ops-alerts, DQ gate, backups, CI health, open issues, metrics report | Run weekly and refine after 2-3 cycles |

### MET (Metrics/KPIs/KRIs)

| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| MET-001 | Metrics | Weekly SLO pack | Required weekly metrics | P0 | Telemetry Owner | DONE | docs/metrics.md; tools/metrics/weekly_metrics.sh; artifacts/metrics/weekly_metrics_YYYY-WW.md | Weekly report exists with thresholds and actions (MTTD/MTTR optional, but health KPIs required) | Run weekly with GOV-003 and tune thresholds after 2-3 cycles |
| MET-002 | Metrics | Trend tracking | Baselines & drift | P1 | Telemetry Owner | TODO | artifacts/telemetry/baselines/*; docs/metrics.md | Baselines for key channels, and alert on deviation | Start with Windows, extend to Linux/pfSense |

---

# Roadmap Waves

## Wave 1 (2 weeks) — Real sources + sustained ops
Goal: not only SIEM+single Windows endpoint. Add Linux endpoint and perimeter telemetry, plus change control and weekly metrics.

### OLA1-LNX (Linux endpoint)
| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| OLA1-LNX-001 | Wave 1 | Linux endpoint | Provision VM + hardening baseline | P0 | SOC Engineer | TODO | docs/infra/ola1-linux-endpoint.md; artifacts/infra/ola1-linux-endpoint_YYYY-MM-DD.md | Linux VM created, SSH keys, updates, minimal hardening, time sync; documented | Create VM `soc-linux-endpoint` |
| OLA1-LNX-002 | Wave 1 | Linux telemetry | Wazuh agent installed + enroll | P0 | SOC Engineer | TODO | docs/runbooks/onboarding/linux/onboarding_linux.md; artifacts/onboarding/linux/* | Agent enrolled and visible; events arriving | Mirror Windows onboarding pattern |
| OLA1-LNX-003 | Wave 1 | Linux DQ | Linux onboarding gate (pass/fail) | P0 | Telemetry Owner + SOC Engineer | TODO | tools/onboarding/linux/linux_onboarding_audit.sh; artifacts/onboarding/linux/*; issue on fail | Gate validates auth.log/syslog (or journald), agent active, syscollector, SCA; exit code + Issue on fail | Define must-have Linux logs |

### OLA1-NET (Perimeter with pfSense)
| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| OLA1-NET-001 | Wave 1 | Perimeter | pfSense VM deployed with WAN/LAN segmentation | P0 | SOC Engineer | TODO | docs/infra/ola1-pfsense.md; artifacts/infra/ola1-pfsense_YYYY-MM-DD.md | pfSense running; LAN network defined; basic rules; mgmt access controlled | Create VM `soc-fw` |
| OLA1-NET-002 | Wave 1 | Network telemetry | Export pfSense logs/telemetry to SIEM | P0 | Telemetry Owner + SOC Engineer | TODO | docs/runbooks/onboarding/network/pfsense_to_siem.md; artifacts/telemetry/network/* | Logs arrive in SIEM (syslog or supported integration); basic parsing validated | Define fields + sourcetype mapping |
| OLA1-NET-003 | Wave 1 | Network DQ | DQ gate for pfSense telemetry | P1 | Telemetry Owner | TODO | tools/dq/network_pfsense_gate.sh; artifacts/dq/network/* | Gate asserts recent events + key fields; Issue on fail | Add to weekly metrics pack |

### OLA1-OPS (Sustained operation)
| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| OLA1-OPS-001 | Wave 1 | Change control | Implement GOV-001 | P0 | SOC Manager + SOC Engineer | DONE | docs/governance/change-control.md; CODEOWNERS; artifacts/governance/gov-001_branch_protection_applied_YYYY-MM-DD.md | PR required + required checks + reviewers | Continue with MET-001 before OLA1-LNX/NET scale-out |
| OLA1-OPS-002 | Wave 1 | Metrics | Implement MET-001 weekly report | P0 | Telemetry Owner | TODO | docs/metrics.md; tools/metrics/weekly_metrics.sh | Weekly report produced and stored in artifacts | Use existing scripts + new sources |

---

## Wave 2 (2–4 weeks) — Case Management + SOAR + TIP (VMs separated)
Goal: operate like a SOC with dedicated case management, automation, and threat intel.

### OLA2-CM (TheHive)
| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| OLA2-CM-001 | Wave 2 | Case management | Deploy TheHive VM + backups | P0 | SOC Engineer | TODO | docs/infra/ola2-thehive.md; artifacts/infra/ola2-thehive_YYYY-MM-DD.md | TheHive reachable; auth configured; backup plan documented | VM `soc-cases` |
| OLA2-CM-002 | Wave 2 | Case workflow | Map Issues -> TheHive (mirror or migration) | P1 | SOC Manager + SOC Analyst L1 | TODO | docs/runbooks/cases/case_workflow.md | Defined workflow: when to create case, what fields, closure criteria | Keep GH as mirror optional |

### OLA2-SOAR (Shuffle)
| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| OLA2-SOAR-001 | Wave 2 | SOAR | Deploy Shuffle VM | P0 | SOC Engineer | TODO | docs/infra/ola2-shuffle.md | Shuffle reachable; secure config; no public exposure | VM `soc-soar` |
| OLA2-SOAR-002 | Wave 2 | Automation | Create 2 workflows (MVP) | P1 | SOC Analyst L2 + SOC Engineer | TODO | docs/runbooks/soar/workflows.md; artifacts/soar/* | Workflow 1: alert -> create case; Workflow 2: enrichment -> attach to case | Integrate with TheHive |

### OLA2-TIP (OpenCTI)
| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| OLA2-TIP-001 | Wave 2 | TIP | Deploy OpenCTI VM | P0 | SOC Engineer | TODO | docs/infra/ola2-opencti.md | OpenCTI reachable; initial connectors configured securely | VM `soc-tip` |
| OLA2-TIP-002 | Wave 2 | Enrichment | TIP enrichment into cases | P1 | SOC Analyst L2 | TODO | docs/runbooks/tip/enrichment.md | IOC lookup in OpenCTI; enrichment attached to TheHive case | Start with 1 connector |

---

## Wave 3 (4–6 weeks) — Vuln Mgmt + NIDS + Adversary Emulation
Goal: add vulnerability pipeline, network detection, and continuous detection testing.

### OLA3-VULN
| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| OLA3-VULN-001 | Wave 3 | Vuln scanning | Deploy scanner VM (tool TBD) | P1 | SOC Engineer | TODO | docs/infra/ola3-vuln-scanner.md | Scanner runs; exports findings | Decide tool |
| OLA3-VULN-002 | Wave 3 | Findings -> cases | Pipeline to TheHive | P1 | SOC Analyst L2 + SOAR | TODO | docs/runbooks/vuln/findings_pipeline.md | Findings create/update cases with SLA | Automate via Shuffle |

### OLA3-NIDS
| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| OLA3-NIDS-001 | Wave 3 | NIDS | Deploy Suricata/Snort VM | P1 | SOC Engineer | TODO | docs/infra/ola3-nids.md | NIDS running and generating events | Pick Suricata or Snort |
| OLA3-NIDS-002 | Wave 3 | NIDS -> SIEM | Ingest NIDS events into SIEM | P1 | Telemetry Owner | TODO | docs/runbooks/onboarding/network/nids_to_siem.md | Events arrive; parsing validated; DQ gate exists | Add to MET weekly |

### OLA3-EMUL
| id | area | capability | sub-capability | priority | owner_role | status | evidence_paths | acceptance_criteria (DoD) | next_action |
|---|---|---|---|---|---|---|---|---|---|
| OLA3-EMUL-001 | Wave 3 | Adversary emulation | Atomic Red Team setup | P1 | SOC Engineer + Detection Eng | TODO | docs/infra/ola3-atomic-red-team.md | Tests runnable; evidence captured | Define safe test set |
| OLA3-EMUL-002 | Wave 3 | Detection regression | Regression suite tied to detections | P1 | Detection Engineer | TODO | docs/runbooks/detections/regression.md; test-events/* | At least 5 tests mapped to detections; PASS/FAIL in CI | Integrate with CI required checks |

---
