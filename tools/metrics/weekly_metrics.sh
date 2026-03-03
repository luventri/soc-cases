#!/usr/bin/env bash
set -euo pipefail

# Weekly metrics pack (MET-001)
# - Consolidates health KPIs from existing artifacts and CI.
# - Output: artifacts/metrics/weekly_metrics_YYYY-WW.md
# - No secrets required or printed.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REF_DATE="${1:-$(date -u +%F)}"

if ! date -u -d "${REF_DATE}" +%F >/dev/null 2>&1; then
  echo "FAIL: invalid date '${REF_DATE}' (expected YYYY-MM-DD)"
  exit 2
fi

WEEK="$(date -u -d "${REF_DATE}" +%G-%V)"
WINDOW_END="$(date -u -d "${REF_DATE}" +%F)"
WINDOW_START="$(date -u -d "${REF_DATE} -6 days" +%F)"
NOW_UTC="$(date -u +'%Y-%m-%d %H:%M UTC')"

OUTDIR="${REPO_ROOT}/artifacts/metrics"
OUT="${OUTDIR}/weekly_metrics_${WEEK}.md"
COVERAGE_DIR="${REPO_ROOT}/artifacts/telemetry/coverage"
OPS_DIR="${REPO_ROOT}/artifacts/platform/ops-alerts"

mkdir -p "${OUTDIR}"

start_epoch="$(date -u -d "${WINDOW_START}" +%s)"
end_epoch="$(date -u -d "${WINDOW_END}" +%s)"

coverage_reports=0
coverage_total_events_sum=0
coverage_latest_file=""
coverage_latest_events=""

if [[ -d "${COVERAGE_DIR}" ]]; then
  while IFS= read -r file; do
    base="$(basename "${file}")"
    file_date="${base#coverage_24h_}"
    file_date="${file_date%.md}"

    if ! epoch="$(date -u -d "${file_date}" +%s 2>/dev/null)"; then
      continue
    fi
    if (( epoch < start_epoch || epoch > end_epoch )); then
      continue
    fi

    coverage_reports=$((coverage_reports + 1))
    events="$(awk -F': ' '/^- Total events \(all\): /{print $2; exit}' "${file}" 2>/dev/null || true)"
    if [[ "${events}" =~ ^[0-9]+$ ]]; then
      coverage_total_events_sum=$((coverage_total_events_sum + events))
    fi

    if [[ -z "${coverage_latest_file}" || "${file_date}" > "${coverage_latest_file}" ]]; then
      coverage_latest_file="${file_date}"
      coverage_latest_events="${events:-N/A}"
    fi
  done < <(find "${COVERAGE_DIR}" -maxdepth 1 -type f -name 'coverage_24h_*.md' | sort)
fi

ops_runs=0
ops_pass=0
ops_fail=0
ops_latest_file=""
ops_latest_result="N/A"

if [[ -d "${OPS_DIR}" ]]; then
  while IFS= read -r file; do
    base="$(basename "${file}")"
    file_date="${base#ops_alerts_}"
    file_date="${file_date%.md}"

    if ! epoch="$(date -u -d "${file_date}" +%s 2>/dev/null)"; then
      continue
    fi
    if (( epoch < start_epoch || epoch > end_epoch )); then
      continue
    fi

    ops_runs=$((ops_runs + 1))
    if rg -q '^\*\*PASS\*\*' "${file}"; then
      ops_pass=$((ops_pass + 1))
      result="PASS"
    elif rg -q '^\*\*FAIL\*\*' "${file}"; then
      ops_fail=$((ops_fail + 1))
      result="FAIL"
    else
      result="UNKNOWN"
    fi

    if [[ -z "${ops_latest_file}" || "${file_date}" > "${ops_latest_file}" ]]; then
      ops_latest_file="${file_date}"
      ops_latest_result="${result}"
    fi
  done < <(find "${OPS_DIR}" -maxdepth 1 -type f -name 'ops_alerts_*.md' | sort)
fi

ci_checked_workflows=0
ci_ok_workflows=0
ci_failed_workflows=0
ci_unknown_workflows=0
ci_note="gh unavailable or unauthenticated"

if command -v gh >/dev/null 2>&1; then
  if gh auth status >/dev/null 2>&1; then
    if ci_raw="$(gh run list --branch main --limit 60 --json workflowName,conclusion,createdAt 2>/dev/null)"; then
      ci_note="from GitHub Actions runs on main within report window"
      if ci_eval="$(python3 - "${ci_raw}" "${WINDOW_START}" "${WINDOW_END}" <<'PY'
import json,sys,datetime
raw=sys.argv[1]
window_start=datetime.datetime.fromisoformat(sys.argv[2]+'T00:00:00+00:00')
window_end=datetime.datetime.fromisoformat(sys.argv[3]+'T23:59:59+00:00')
runs=json.loads(raw)
workflows=[
  'Secret scanning (gitleaks)',
  'Security policy checks',
  'Lint and audit controls',
]
latest={name:None for name in workflows}
for r in runs:
  w=r.get('workflowName')
  if w not in latest:
    continue
  created=r.get('createdAt')
  if not created:
    continue
  dt=datetime.datetime.fromisoformat(created.replace('Z','+00:00'))
  if dt < window_start or dt > window_end:
    continue
  prev=latest[w]
  if prev is None or dt > prev[0]:
    latest[w]=(dt, (r.get('conclusion') or '').lower())
checked=ok=failed=unknown=0
for name in workflows:
  x=latest[name]
  if x is None:
    unknown += 1
    continue
  checked += 1
  c=x[1]
  if c == 'success':
    ok += 1
  elif c in ('failure','timed_out','cancelled','startup_failure','action_required','stale'):
    failed += 1
  else:
    unknown += 1
print(f"{checked}|{ok}|{failed}|{unknown}")
PY
)"; then
        IFS='|' read -r ci_checked_workflows ci_ok_workflows ci_failed_workflows ci_unknown_workflows <<< "${ci_eval}"
      fi
    fi
  else
    ci_note="gh present but not authenticated"
  fi
fi

kpi_cov_status="PASS"
kpi_cov_action="No action"
if (( coverage_reports < 5 )); then
  kpi_cov_status="FAIL"
  kpi_cov_action="Generate missing coverage_24h reports and validate scheduler"
elif [[ -n "${coverage_latest_events}" && "${coverage_latest_events}" =~ ^[0-9]+$ && ${coverage_latest_events} -eq 0 ]]; then
  kpi_cov_status="FAIL"
  kpi_cov_action="Investigate ingest pipeline: latest coverage report has zero events"
fi

kpi_ops_status="PASS"
kpi_ops_action="No action"
if (( ops_runs < 5 )); then
  kpi_ops_status="FAIL"
  kpi_ops_action="Restore/verify ops-alerts cadence (timer or manual run)"
elif (( ops_fail > 1 )); then
  kpi_ops_status="FAIL"
  kpi_ops_action="Open/track remediation for recurring ops-alerts failures"
elif (( ops_fail == 1 )); then
  kpi_ops_status="WARN"
  kpi_ops_action="Confirm single failure is contained and ticketed"
fi

kpi_ci_status="PASS"
kpi_ci_action="No action"
if (( ci_checked_workflows == 0 )); then
  kpi_ci_status="WARN"
  kpi_ci_action="Review Actions UI manually and restore gh access for automation"
elif (( ci_failed_workflows > 0 )); then
  kpi_ci_status="FAIL"
  kpi_ci_action="Fix failing required checks before high-risk merges"
elif (( ci_unknown_workflows > 0 )); then
  kpi_ci_status="WARN"
  kpi_ci_action="Investigate missing/partial workflow results in last 7 days"
fi

overall="PASS"
if [[ "${kpi_cov_status}" == "FAIL" || "${kpi_ops_status}" == "FAIL" || "${kpi_ci_status}" == "FAIL" ]]; then
  overall="FAIL"
elif [[ "${kpi_cov_status}" == "WARN" || "${kpi_ops_status}" == "WARN" || "${kpi_ci_status}" == "WARN" ]]; then
  overall="WARN"
fi

{
  echo "# Weekly metrics pack ${WEEK} (MET-001)"
  echo
  echo "- Generated (UTC): ${NOW_UTC}"
  echo "- Window (UTC): ${WINDOW_START} .. ${WINDOW_END}"
  echo "- Sources: artifacts/telemetry/coverage, artifacts/platform/ops-alerts, GitHub Actions"
  echo
  echo "## KPI table"
  echo
  echo "| KPI | Value | Threshold | Status | Action |"
  echo "|---|---:|---|---|---|"
  echo "| Coverage evidence days | ${coverage_reports}/7 | >=5 reports/week and latest events > 0 | ${kpi_cov_status} | ${kpi_cov_action} |"
  echo "| Ops alerts reliability | runs=${ops_runs}, pass=${ops_pass}, fail=${ops_fail} | >=5 runs/week and <=1 fail/week | ${kpi_ops_status} | ${kpi_ops_action} |"
  echo "| Required CI controls | checked=${ci_checked_workflows}, ok=${ci_ok_workflows}, fail=${ci_failed_workflows}, unknown=${ci_unknown_workflows} | gitleaks + policy + lint-audit healthy in last 7d | ${kpi_ci_status} | ${kpi_ci_action} |"
  echo
  echo "## Details"
  echo
  echo "### Coverage"
  echo "- Reports found in window: ${coverage_reports}"
  echo "- Total events sum (available reports): ${coverage_total_events_sum}"
  echo "- Latest coverage artifact date: ${coverage_latest_file:-N/A}"
  echo "- Latest coverage total events: ${coverage_latest_events:-N/A}"
  echo
  echo "### Ops alerts"
  echo "- Runs found in window: ${ops_runs}"
  echo "- PASS: ${ops_pass}"
  echo "- FAIL: ${ops_fail}"
  echo "- Latest ops-alert artifact date: ${ops_latest_file:-N/A}"
  echo "- Latest ops-alert result: ${ops_latest_result}"
  echo
  echo "### CI controls"
  echo "- Workflows evaluated: Secret scanning (gitleaks), Security policy checks, Lint and audit controls"
  echo "- Data note: ${ci_note}"
  echo "- Last-7d summary: checked=${ci_checked_workflows}, ok=${ci_ok_workflows}, fail=${ci_failed_workflows}, unknown=${ci_unknown_workflows}"
  echo
  echo "## Optional incident metrics"
  echo "- MTTD: N/A (not instrumented yet)"
  echo "- MTTR: N/A (not instrumented yet)"
  echo
  echo "## Weekly result"
  if [[ "${overall}" == "PASS" ]]; then
    echo "**PASS** - Weekly health KPIs meet baseline thresholds."
  elif [[ "${overall}" == "WARN" ]]; then
    echo "**WARN** - Weekly baseline is partially met; follow actions before high-risk changes."
  else
    echo "**FAIL** - Weekly baseline not met; prioritize corrective actions before risky merges."
  fi
} > "${OUT}"

echo "OK: wrote ${OUT}"
