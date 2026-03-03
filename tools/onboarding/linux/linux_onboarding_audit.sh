#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  tools/onboarding/linux/linux_onboarding_audit.sh --agent "<AGENT_NAME>" [--date YYYY-MM-DD]

Required:
  --agent  Agent name in Wazuh (example: soc-linux-endpoint)

Optional:
  --date   YYYY-MM-DD (default: today)

Exit code:
  0 when all MUST checks pass (M1-M5). M6 may be WARN.
USAGE
}

AGENT=""
DATE="$(date +%F)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent) AGENT="${2:-}"; shift 2 ;;
    --date) DATE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "FAIL: unknown arg: $1"; usage; exit 2 ;;
  esac
done

if [[ -z "${AGENT}" ]]; then
  echo "FAIL: --agent is required"
  usage
  exit 2
fi

SECRETS_FILE="${HOME}/.secrets/mini-soc.env"
if [[ ! -f "${SECRETS_FILE}" ]]; then
  echo "FAIL: missing secrets file ${SECRETS_FILE}"
  exit 2
fi

# shellcheck disable=SC1090
set -a
source "${SECRETS_FILE}"
set +a

if [[ -z "${WAZUH_API_USER:-}" || -z "${WAZUH_API_PASS:-}" ]]; then
  echo "FAIL: missing WAZUH_API_USER/WAZUH_API_PASS"
  exit 2
fi
if [[ -z "${WAZUH_INDEXER_USER:-}" || -z "${WAZUH_INDEXER_PASS:-}" ]]; then
  echo "FAIL: missing WAZUH_INDEXER_USER/WAZUH_INDEXER_PASS"
  exit 2
fi

INDEXER_HOST="${OPS_INDEXER_HOSTNAME:-wazuh.indexer}"
INDEXER_ADDR="${OPS_INDEXER_ADDR:-127.0.0.1}"
INDEXER_URL="${OPS_INDEXER_URL:-https://${INDEXER_HOST}:9200}"
INDEXER_CA="${OPS_INDEXER_CA:-/home/socadmin/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem}"
ARCHIVES_INDEX="${OPS_ARCHIVES_INDEX:-wazuh-archives-4.x-*}"
WAZUH_API_URL="${OPS_WAZUH_API_URL:-https://127.0.0.1:55000}"

if [[ ! -f "${INDEXER_CA}" ]]; then
  echo "FAIL: missing indexer CA file: ${INDEXER_CA}"
  exit 2
fi

CURL_TLS=(--cacert "${INDEXER_CA}")
if [[ "${INDEXER_URL}" == "https://${INDEXER_HOST}:9200"* ]]; then
  CURL_TLS+=(--resolve "${INDEXER_HOST}:9200:${INDEXER_ADDR}")
fi

OUTDIR="${REPO_ROOT}/artifacts/onboarding/linux"
mkdir -p "${OUTDIR}"

M1="${OUTDIR}/M1_agent_active_${DATE}.md"
M2="${OUTDIR}/M2_ingest_freshness_${DATE}.md"
M3="${OUTDIR}/M3_linux_log_signal_${DATE}.md"
M4="${OUTDIR}/M4_identity_consistency_${DATE}.md"
M5="${OUTDIR}/M5_syscollector_${DATE}.md"
M6="${OUTDIR}/M6_sca_${DATE}.md"
RUN_LOG="${OUTDIR}/gate_run_${DATE}.log"

# write all script output to run log + stdout
exec > >(tee "${RUN_LOG}") 2>&1

active_min=15
ingest_min=60
linux_signal_hours=24
syscollector_hours=24
sca_hours=24

api_token() {
  curl -sk -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" -X POST "${WAZUH_API_URL}/security/user/authenticate?raw=true"
}

WAPI_TOKEN="$(api_token)"
if [[ -z "${WAPI_TOKEN}" ]]; then
  echo "FAIL: could not obtain Wazuh API token"
  exit 2
fi

fail_mark=0
warn_mark=0
AGENT_ID=""
AGENT_API_NAME=""
AGENT_LAST_KEEPALIVE=""
LATEST_EVENT_AGENT=""
SYSCOLLECTOR_HOSTNAME=""

# M1 - agent active (MUST)
{
  echo "# M1 — Agent active"
  echo
  echo "- date: ${DATE}"
  echo "- agent.expected: ${AGENT}"
} > "${M1}"

curl -sk -H "Authorization: Bearer ${WAPI_TOKEN}" "${WAZUH_API_URL}/agents?search=${AGENT}" -o /tmp/lnx_m1.json
python3 - "${AGENT}" "${M1}" "${active_min}" <<'PY'
import json,sys,datetime
agent=sys.argv[1]
out=sys.argv[2]
active_min=int(sys.argv[3])
j=json.load(open('/tmp/lnx_m1.json',encoding='utf-8'))
items=(j.get('data') or {}).get('affected_items') or []
match=None
for it in items:
    if (it.get('name') or '').lower()==agent.lower():
        match=it
        break
if not match and items:
    match=items[0]
with open(out,'a',encoding='utf-8') as f:
    if not match:
        f.write('RESULT: FAIL (agent not found)\n')
        print('M1R=FAIL')
        sys.exit(0)
    status=(match.get('status') or '').lower()
    lk=match.get('lastKeepAlive')
    f.write(f"- agent.id: {match.get('id')}\n")
    f.write(f"- agent.name: {match.get('name')}\n")
    f.write(f"- status: {match.get('status')}\n")
    f.write(f"- lastKeepAlive: {lk}\n")
    f.write(f"- version: {match.get('version')}\n")
    f.write(f"- ip: {match.get('ip')}\n")
    if status!='active' or not lk:
        f.write('RESULT: FAIL (agent not active or missing keepalive)\n')
        print('M1R=FAIL')
        sys.exit(0)
    try:
        ts=datetime.datetime.fromisoformat(lk.replace('Z','+00:00'))
        now=datetime.datetime.now(datetime.timezone.utc)
        age=(now-ts).total_seconds()
        if age > active_min*60:
            f.write(f"- freshness: FAIL (age_seconds={int(age)}, threshold_seconds={active_min*60})\n")
            f.write('RESULT: FAIL (stale keepalive)\n')
            print('M1R=FAIL')
            sys.exit(0)
        f.write(f"- freshness: PASS (age_seconds={int(age)}, threshold_seconds={active_min*60})\n")
    except Exception:
        f.write('- freshness: FAIL (unparseable lastKeepAlive)\n')
        f.write('RESULT: FAIL (unparseable keepalive)\n')
        print('M1R=FAIL')
        sys.exit(0)
    f.write('RESULT: PASS\n')
    print('M1R=PASS')
    print(f"AGENT_ID={match.get('id')}")
    print(f"AGENT_API_NAME={match.get('name')}")
    print(f"AGENT_LAST_KEEPALIVE={lk}")
PY
M1R="$(grep -q '^RESULT: PASS' "${M1}" && echo PASS || echo FAIL)"
if [[ "${M1R}" == "PASS" ]]; then
  AGENT_ID="$(awk -F': ' '/^- agent.id:/{print $2; exit}' "${M1}")"
  AGENT_API_NAME="$(awk -F': ' '/^- agent.name:/{print $2; exit}' "${M1}")"
  AGENT_LAST_KEEPALIVE="$(awk -F': ' '/^- lastKeepAlive:/{print $2; exit}' "${M1}")"
else
  fail_mark=1
fi

# M2 - ingest freshness in archives (MUST)
PAY_M2="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"agent.name\":\"${AGENT}\"}},{\"range\":{\"@timestamp\":{\"gte\":\"now-${ingest_min}m\"}}}]}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"agent.name\",\"decoder.name\",\"location\"]}"
curl -sS "${CURL_TLS[@]}" -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" -H 'Content-Type: application/json' "${INDEXER_URL}/${ARCHIVES_INDEX}/_search" -d "${PAY_M2}" -o /tmp/lnx_m2.json
python3 - "${M2}" <<'PY'
import json,sys
out=sys.argv[1]
j=json.load(open('/tmp/lnx_m2.json',encoding='utf-8'))
h=(j.get('hits') or {}).get('hits') or []
with open(out,'w',encoding='utf-8') as f:
    f.write('# M2 — Linux ingest freshness\n\n')
    if not h:
        f.write('RESULT: FAIL (no recent events in archives window)\n')
    else:
        s=h[0].get('_source',{})
        f.write(f"- @timestamp: {s.get('@timestamp')}\n")
        f.write(f"- agent.name: {(s.get('agent') or {}).get('name')}\n")
        f.write(f"- decoder.name: {(s.get('decoder') or {}).get('name')}\n")
        f.write(f"- location: {s.get('location')}\n")
        f.write('RESULT: PASS\n')
PY
M2R="$(grep -q '^RESULT: PASS' "${M2}" && echo PASS || echo FAIL)"
if [[ "${M2R}" == "FAIL" ]]; then fail_mark=1; fi
LATEST_EVENT_AGENT="$(awk -F': ' '/^- agent.name:/{print $2; exit}' "${M2}" || true)"

# M3 - linux log signal (MUST): pam/sudo/systemd in last 24h
PAY_M3="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"agent.name\":\"${AGENT}\"}},{\"range\":{\"@timestamp\":{\"gte\":\"now-${linux_signal_hours}h\"}}}],\"should\":[{\"term\":{\"decoder.name\":\"pam\"}},{\"term\":{\"decoder.name\":\"sudo\"}},{\"term\":{\"decoder.name\":\"systemd\"}}],\"minimum_should_match\":1}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"agent.name\",\"decoder.name\",\"location\"]}"
curl -sS "${CURL_TLS[@]}" -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" -H 'Content-Type: application/json' "${INDEXER_URL}/${ARCHIVES_INDEX}/_search" -d "${PAY_M3}" -o /tmp/lnx_m3.json
python3 - "${M3}" <<'PY'
import json,sys
out=sys.argv[1]
j=json.load(open('/tmp/lnx_m3.json',encoding='utf-8'))
h=(j.get('hits') or {}).get('hits') or []
with open(out,'w',encoding='utf-8') as f:
    f.write('# M3 — Linux log signal (pam/sudo/systemd)\n\n')
    if not h:
        f.write('RESULT: FAIL (no linux auth/log signal in window)\n')
    else:
        s=h[0].get('_source',{})
        f.write(f"- @timestamp: {s.get('@timestamp')}\n")
        f.write(f"- agent.name: {(s.get('agent') or {}).get('name')}\n")
        f.write(f"- decoder.name: {(s.get('decoder') or {}).get('name')}\n")
        f.write(f"- location: {s.get('location')}\n")
        f.write('RESULT: PASS\n')
PY
M3R="$(grep -q '^RESULT: PASS' "${M3}" && echo PASS || echo FAIL)"
if [[ "${M3R}" == "FAIL" ]]; then fail_mark=1; fi

# M5 - syscollector freshness (MUST)
{
  echo "# M5 — Syscollector freshness"
  echo
  echo "- agent: ${AGENT}"
} > "${M5}"
if [[ -z "${AGENT_ID}" ]]; then
  echo "RESULT: FAIL (missing agent id from M1)" >> "${M5}"
  M5R="FAIL"
  fail_mark=1
else
  code_os="$(curl -sk -o /tmp/lnx_m5_os.json -w '%{http_code}' -H "Authorization: Bearer ${WAPI_TOKEN}" "${WAZUH_API_URL}/syscollector/${AGENT_ID}/os")"
  code_pkg="$(curl -sk -o /tmp/lnx_m5_pkg.json -w '%{http_code}' -H "Authorization: Bearer ${WAPI_TOKEN}" "${WAZUH_API_URL}/syscollector/${AGENT_ID}/packages?limit=1")"
  if [[ "${code_os}" != "200" || "${code_pkg}" != "200" ]]; then
    echo "RESULT: FAIL (syscollector API HTTP os=${code_os} pkg=${code_pkg})" >> "${M5}"
    M5R="FAIL"
    fail_mark=1
  else
    python3 - "${M5}" "${syscollector_hours}" <<'PY'
import json,sys,datetime
out=sys.argv[1]
max_h=int(sys.argv[2])
osj=json.load(open('/tmp/lnx_m5_os.json',encoding='utf-8'))
pj=json.load(open('/tmp/lnx_m5_pkg.json',encoding='utf-8'))
os_items=(osj.get('data') or {}).get('affected_items') or []
p_items=(pj.get('data') or {}).get('affected_items') or []
with open(out,'a',encoding='utf-8') as f:
    f.write(f"- os.items: {len(os_items)}\n")
    f.write(f"- packages.items(limit=1): {len(p_items)}\n")
    if not os_items or not p_items:
        f.write('RESULT: FAIL (missing syscollector data)\n')
        print('M5R=FAIL')
        sys.exit(0)
    host=os_items[0].get('hostname')
    scan=os_items[0].get('scan') or {}
    scan_t=scan.get('time') or scan.get('start') or scan.get('end')
    f.write(f"- hostname: {host}\n")
    f.write(f"- scan.time: {scan_t}\n")
    fresh=True
    if scan_t:
      try:
        ts=datetime.datetime.fromisoformat(scan_t.replace('Z','+00:00'))
        age=(datetime.datetime.now(datetime.timezone.utc)-ts).total_seconds()
        if age > max_h*3600:
          fresh=False
          f.write(f"- freshness: FAIL (age_seconds={int(age)}, threshold_seconds={max_h*3600})\n")
        else:
          f.write(f"- freshness: PASS (age_seconds={int(age)}, threshold_seconds={max_h*3600})\n")
      except Exception:
        f.write('- freshness: WARN (unparseable scan.time)\n')
    else:
      f.write('- freshness: WARN (scan.time unavailable)\n')
    if not fresh:
      f.write('RESULT: FAIL (stale syscollector scan)\n')
      print('M5R=FAIL')
    else:
      f.write('RESULT: PASS\n')
      print('M5R=PASS')
      print(f"SYSCOLLECTOR_HOSTNAME={host}")
PY
    M5R="$(grep -q '^RESULT: PASS' "${M5}" && echo PASS || echo FAIL)"
    SYSCOLLECTOR_HOSTNAME="$(awk -F': ' '/^- hostname:/{print $2; exit}' "${M5}" || true)"
    if [[ "${M5R}" == "FAIL" ]]; then fail_mark=1; fi
  fi
fi

# M4 - identity consistency (MUST)
{
  echo "# M4 — Identity consistency"
  echo
  echo "- expected.agent: ${AGENT}"
  echo "- api.agent.name: ${AGENT_API_NAME:-N/A}"
  echo "- latest.event.agent: ${LATEST_EVENT_AGENT:-N/A}"
  echo "- syscollector.hostname: ${SYSCOLLECTOR_HOSTNAME:-N/A}"
  if [[ -n "${AGENT_API_NAME}" && "${AGENT_API_NAME}" == "${AGENT}" && -n "${LATEST_EVENT_AGENT}" && "${LATEST_EVENT_AGENT}" == "${AGENT}" ]]; then
    if [[ -n "${SYSCOLLECTOR_HOSTNAME}" && "${SYSCOLLECTOR_HOSTNAME}" != "N/A" && "${SYSCOLLECTOR_HOSTNAME}" != "${AGENT}" ]]; then
      echo "RESULT: FAIL (syscollector hostname mismatch)"
    else
      echo "RESULT: PASS"
    fi
  else
    echo "RESULT: FAIL (agent identity mismatch)"
  fi
} > "${M4}"
M4R="$(grep -q '^RESULT: PASS' "${M4}" && echo PASS || echo FAIL)"
if [[ "${M4R}" == "FAIL" ]]; then fail_mark=1; fi

# M6 - SCA freshness (WARN allowed)
{
  echo "# M6 — SCA freshness"
  echo
  echo "- agent: ${AGENT}"
} > "${M6}"
if [[ -z "${AGENT_ID}" ]]; then
  echo "RESULT: WARN (missing agent id from M1)" >> "${M6}"
  M6R="WARN"
  warn_mark=1
else
  code_sca="$(curl -sk -o /tmp/lnx_m6_sca.json -w '%{http_code}' -H "Authorization: Bearer ${WAPI_TOKEN}" "${WAZUH_API_URL}/sca/${AGENT_ID}?limit=1")"
  if [[ "${code_sca}" != "200" ]]; then
    echo "RESULT: WARN (SCA API HTTP=${code_sca})" >> "${M6}"
    M6R="WARN"
    warn_mark=1
  else
    python3 - "${M6}" "${sca_hours}" <<'PY'
import json,sys,datetime
out=sys.argv[1]
max_h=int(sys.argv[2])
j=json.load(open('/tmp/lnx_m6_sca.json',encoding='utf-8'))
items=(j.get('data') or {}).get('affected_items') or []
with open(out,'a',encoding='utf-8') as f:
    f.write(f"- sca.items(limit=1): {len(items)}\n")
    if not items:
        f.write('RESULT: WARN (no SCA data yet)\n')
        print('M6R=WARN')
        sys.exit(0)
    item=items[0]
    scan=item.get('scan_time') or item.get('end_scan') or item.get('start_scan')
    f.write(f"- policy.id: {item.get('policy_id')}\n")
    f.write(f"- scan_time: {scan}\n")
    if scan:
      try:
        ts=datetime.datetime.fromisoformat(scan.replace('Z','+00:00'))
        age=(datetime.datetime.now(datetime.timezone.utc)-ts).total_seconds()
        if age > max_h*3600:
          f.write(f"- freshness: WARN (age_seconds={int(age)}, threshold_seconds={max_h*3600})\n")
          f.write('RESULT: WARN (stale SCA data)\n')
          print('M6R=WARN')
          sys.exit(0)
        f.write(f"- freshness: PASS (age_seconds={int(age)}, threshold_seconds={max_h*3600})\n")
      except Exception:
        f.write('- freshness: WARN (unparseable scan_time)\n')
        f.write('RESULT: WARN\n')
        print('M6R=WARN')
        sys.exit(0)
    f.write('RESULT: PASS\n')
    print('M6R=PASS')
PY
    M6R="$(grep -q '^RESULT: PASS' "${M6}" && echo PASS || echo WARN)"
    if [[ "${M6R}" == "WARN" ]]; then warn_mark=1; fi
  fi
fi

echo "SUMMARY:"
echo "- M1 Agent active         : ${M1R} -> ${M1}"
echo "- M2 Ingest freshness     : ${M2R} -> ${M2}"
echo "- M3 Linux log signal     : ${M3R} -> ${M3}"
echo "- M4 Identity consistency : ${M4R} -> ${M4}"
echo "- M5 Syscollector         : ${M5R} -> ${M5}"
echo "- M6 SCA                  : ${M6R} -> ${M6}"

if [[ "${fail_mark}" -eq 0 ]]; then
  if [[ "${warn_mark}" -eq 1 ]]; then
    echo "FINAL: PASS_WITH_WARN (MUST passed, SCA warning allowed)"
  else
    echo "FINAL: PASS (all checks passed)"
  fi
  exit 0
fi

echo "FINAL: FAIL (one or more MUST checks failed)"

ISSUE_BODY="${OUTDIR}/gate_fail_${DATE}.md"
{
  echo "# Linux onboarding gate — FAIL"
  echo
  echo "- date: ${DATE}"
  echo "- agent: ${AGENT}"
  echo
  echo "## Summary"
  echo "- M1 Agent active: ${M1R}"
  echo "- M2 Ingest freshness: ${M2R}"
  echo "- M3 Linux log signal: ${M3R}"
  echo "- M4 Identity consistency: ${M4R}"
  echo "- M5 Syscollector: ${M5R}"
  echo "- M6 SCA: ${M6R}"
  echo
  echo "## Artifacts"
  echo "- ${M1}"
  echo "- ${M2}"
  echo "- ${M3}"
  echo "- ${M4}"
  echo "- ${M5}"
  echo "- ${M6}"
  echo "- ${RUN_LOG}"
  echo
  echo "## Result"
  echo "**FAIL**"
} > "${ISSUE_BODY}"

ISSUE_TITLE="Linux onboarding gate FAIL (${AGENT}) ${DATE}"
"${REPO_ROOT}/tools/onboarding/linux/create_issue_on_fail.sh" "${ISSUE_TITLE}" "${ISSUE_BODY}" || true

exit 1
