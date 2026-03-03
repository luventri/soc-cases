#!/usr/bin/env bash
set -euo pipefail

# MET-002: baseline and drift tracking for key Windows channels.
# Inputs: artifacts/telemetry/coverage/coverage_24h_YYYY-MM-DD.md
# Outputs:
#   - artifacts/telemetry/baselines/windows_channel_baseline_YYYY-MM-DD.json
#   - artifacts/telemetry/baselines/windows_channel_baseline_drift_YYYY-MM-DD.md

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REF_DATE="${1:-$(date -u +%F)}"

if ! date -u -d "${REF_DATE}" +%F >/dev/null 2>&1; then
  echo "FAIL: invalid date '${REF_DATE}' (expected YYYY-MM-DD)"
  exit 2
fi

LOOKBACK_DAYS="${MET_BASELINE_LOOKBACK_DAYS:-14}"
DRIFT_PCT_THRESHOLD="${MET_DRIFT_THRESHOLD_PCT:-40}"
MIN_BASELINE_SAMPLES="${MET_MIN_BASELINE_SAMPLES:-3}"
CHANNELS_CSV="${MET_CHANNELS_CSV:-Security,Microsoft-Windows-Sysmon/Operational,System,Application}"
CREATE_ISSUE_ON_FAIL="${MET_CREATE_ISSUE_ON_FAIL:-0}"

COVERAGE_DIR="${REPO_ROOT}/artifacts/telemetry/coverage"
OUTDIR="${REPO_ROOT}/artifacts/telemetry/baselines"
JSON_OUT="${OUTDIR}/windows_channel_baseline_${REF_DATE}.json"
MD_OUT="${OUTDIR}/windows_channel_baseline_drift_${REF_DATE}.md"

mkdir -p "${OUTDIR}"

window_start="$(date -u -d "${REF_DATE} -${LOOKBACK_DAYS} days" +%F)"

python3 - "${COVERAGE_DIR}" "${window_start}" "${REF_DATE}" "${CHANNELS_CSV}" "${DRIFT_PCT_THRESHOLD}" "${MIN_BASELINE_SAMPLES}" "${JSON_OUT}" "${MD_OUT}" <<'PY'
import datetime as dt
import json
import pathlib
import re
import statistics
import sys

coverage_dir = pathlib.Path(sys.argv[1])
window_start = dt.date.fromisoformat(sys.argv[2])
ref_date = dt.date.fromisoformat(sys.argv[3])
channels = [x.strip() for x in sys.argv[4].split(',') if x.strip()]
drift_threshold = float(sys.argv[5])
min_samples = int(sys.argv[6])
json_out = pathlib.Path(sys.argv[7])
md_out = pathlib.Path(sys.argv[8])

pat = re.compile(r'^coverage_24h_(\d{4}-\d{2}-\d{2})\.md$')

def parse_file(path: pathlib.Path):
    day = None
    m = pat.match(path.name)
    if not m:
        return None
    day = dt.date.fromisoformat(m.group(1))
    lines = path.read_text(encoding='utf-8').splitlines()
    section = False
    chan = {}
    for ln in lines:
        if ln.startswith('## Top Windows channels'):
            section = True
            continue
        if section and ln.startswith('## '):
            break
        if section:
            mm = re.match(r'^-\s+(.+?):\s+(\d+)$', ln)
            if mm:
                chan[mm.group(1)] = int(mm.group(2))
    return {'date': day.isoformat(), 'channels': chan}

rows = []
if coverage_dir.exists():
    for p in sorted(coverage_dir.glob('coverage_24h_*.md')):
        parsed = parse_file(p)
        if not parsed:
            continue
        d = dt.date.fromisoformat(parsed['date'])
        if window_start <= d <= ref_date:
            rows.append(parsed)

if not rows:
    data = {
      'reference_date': ref_date.isoformat(),
      'window_start': window_start.isoformat(),
      'window_end': ref_date.isoformat(),
      'status': 'FAIL',
      'reason': 'No coverage artifacts found in selected window',
      'channels': [],
      'reports_in_window': 0,
    }
    json_out.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    md_out.write_text(
      '# Windows channel baseline + drift\n\n'
      f'- Reference date (UTC): {ref_date.isoformat()}\n'
      f'- Window (UTC): {window_start.isoformat()} .. {ref_date.isoformat()}\n\n'
      '## Result\n\n'
      '**FAIL** - No coverage artifacts found in window.\n',
      encoding='utf-8'
    )
    print('FAIL: no coverage artifacts in window')
    sys.exit(1)

rows_by_date = {r['date']: r for r in rows}
latest_date = max(rows_by_date)
latest = rows_by_date[latest_date]
history = [r for r in rows if r['date'] != latest_date]

result_rows = []
overall = 'PASS'

for ch in channels:
    hist_vals = [r['channels'].get(ch, 0) for r in history]
    latest_val = latest['channels'].get(ch, 0)
    sample_count = len(hist_vals)

    if sample_count > 0:
        baseline_mean = statistics.mean(hist_vals)
        baseline_median = statistics.median(hist_vals)
    else:
        baseline_mean = 0.0
        baseline_median = 0.0

    if baseline_mean > 0:
        drift_pct = ((latest_val - baseline_mean) / baseline_mean) * 100.0
    else:
        drift_pct = 0.0 if latest_val == 0 else 100.0

    status = 'PASS'
    action = 'No action'

    if sample_count < min_samples:
        status = 'WARN'
        action = 'Collect more daily coverage reports to stabilize baseline'
    elif baseline_mean >= 50 and abs(drift_pct) > drift_threshold:
        status = 'FAIL'
        action = 'Investigate telemetry change and open remediation issue'

    if status == 'FAIL':
        overall = 'FAIL'
    elif status == 'WARN' and overall == 'PASS':
        overall = 'WARN'

    result_rows.append({
      'channel': ch,
      'latest_count': int(latest_val),
      'baseline_mean': round(float(baseline_mean), 2),
      'baseline_median': round(float(baseline_median), 2),
      'history_samples': sample_count,
      'drift_pct': round(float(drift_pct), 2),
      'status': status,
      'action': action,
    })

data = {
  'reference_date': ref_date.isoformat(),
  'window_start': window_start.isoformat(),
  'window_end': ref_date.isoformat(),
  'latest_coverage_date': latest_date,
  'reports_in_window': len(rows),
  'drift_threshold_pct': drift_threshold,
  'min_baseline_samples': min_samples,
  'status': overall,
  'channels': result_rows,
}
json_out.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')

lines = []
lines.append('# Windows channel baseline + drift')
lines.append('')
lines.append(f'- Reference date (UTC): {ref_date.isoformat()}')
lines.append(f'- Window (UTC): {window_start.isoformat()} .. {ref_date.isoformat()}')
lines.append(f'- Latest coverage artifact used: {latest_date}')
lines.append(f'- Coverage reports in window: {len(rows)}')
lines.append(f'- Drift threshold: +/-{drift_threshold:.0f}% (for channels with baseline mean >= 50)')
lines.append(f'- Minimum baseline samples required: {min_samples}')
lines.append('')
lines.append('## Channel drift table')
lines.append('')
lines.append('| Channel | Latest | Baseline mean | Baseline median | Samples | Drift % | Status | Action |')
lines.append('|---|---:|---:|---:|---:|---:|---|---|')
for r in result_rows:
    lines.append(
      f"| {r['channel']} | {r['latest_count']} | {r['baseline_mean']} | {r['baseline_median']} | {r['history_samples']} | {r['drift_pct']} | {r['status']} | {r['action']} |"
    )
lines.append('')
lines.append('## Result')
lines.append('')
if overall == 'PASS':
    lines.append('**PASS** - Baselines stable and no channel exceeds drift threshold.')
elif overall == 'WARN':
    lines.append('**WARN** - Baseline exists but sample size is still limited for at least one channel.')
else:
    lines.append('**FAIL** - One or more channels exceed drift threshold; investigate immediately.')

md_out.write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(f'OK: wrote {json_out}')
print(f'OK: wrote {md_out}')
print(f'OVERALL_STATUS={overall}')
PY

if [[ -f "${JSON_OUT}" ]]; then
  status="$(python3 - "${JSON_OUT}" <<'PY'
import json,sys
print(json.load(open(sys.argv[1], encoding='utf-8')).get('status','UNKNOWN'))
PY
)"

  if [[ "${status}" == "FAIL" && "${CREATE_ISSUE_ON_FAIL}" == "1" ]] && command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    title="MET-002 drift alert: windows channels (${REF_DATE})"
    gh issue create \
      --title "${title}" \
      --label "telemetry,metrics,drift" \
      --body "Automated drift alert from tools/metrics/windows_channel_baseline_drift.sh\n\nArtifact: ${MD_OUT}" >/dev/null || true
    echo "WARN: drift issue creation attempted"
  fi
fi
