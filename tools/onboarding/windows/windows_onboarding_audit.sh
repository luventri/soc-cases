#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  tools/onboarding/windows/windows_onboarding_audit.sh --host "<HOSTNAME>" --agent "<AGENT_NAME>" [--date YYYY-MM-DD]

Required:
  --host   Hostname for M2/M3 (matches data.win.system.computer)
  --agent  Agent name for M5/M6 + M1 (matches agent.name)

Optional:
  --date   YYYY-MM-DD (default: today)

Exit code:
  0 only if ALL MUST checks PASS (M1/M2/M3/M4/M5/M6) including freshness gates.
USAGE
}

HOST=""
AGENT=""
DATE="$(date +%F)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)  HOST="${2:-}"; shift 2 ;;
    --agent) AGENT="${2:-}"; shift 2 ;;
    --date)  DATE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "FAIL: unknown arg: $1"; usage; exit 2 ;;
  esac
done

if [[ -z "${HOST}" || -z "${AGENT}" ]]; then
  echo "FAIL: --host and --agent are required"
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

if [[ -z "${WAZUH_INDEXER_USER:-}" || -z "${WAZUH_INDEXER_PASS:-}" ]]; then
  echo "FAIL: missing WAZUH_INDEXER_USER/WAZUH_INDEXER_PASS in environment"
  exit 2
fi

INDEXER_URL="${OPS_INDEXER_URL:-https://127.0.0.1:9200}"
ARCHIVES_INDEX="${OPS_ARCHIVES_INDEX:-wazuh-archives-4.x-*}"

OUTDIR="artifacts/onboarding/windows"
mkdir -p "${OUTDIR}"

M1="${OUTDIR}/M1_agent_active_${DATE}.md"
M2="${OUTDIR}/M2_security_${DATE}.md"
M3="${OUTDIR}/M3_sysmon_${DATE}.md"
M4="${OUTDIR}/M4_hostname_consistency_${DATE}.md"
M5="${OUTDIR}/M5_syscollector_${DATE}.md"
M6="${OUTDIR}/M6_sca_${DATE}.md"

FRESH_HOURS_ONBOARDING=24
ACTIVE_MIN_ONBOARDING=15

set_result_fail() {
  # Replace first RESULT: PASS with a FAIL reason (keeps artifact multiline, auditable)
  local file="$1"
  local reason="$2"
  if grep -q '^RESULT: PASS' "$file"; then
    sed -i "0,/^RESULT: PASS/{s/^RESULT: PASS/RESULT: FAIL (${reason})/}" "$file"
  elif ! grep -q '^RESULT:' "$file"; then
    printf 'RESULT: FAIL (%s)\n' "$reason" >> "$file"
  fi
}

append_line() {
  local file="$1"; shift
  printf '%s\n' "$*" >> "$file"
}

enforce_freshness_hours() {
  local file="$1"
  local max_hours="$2"

  local ts_line ts epoch_now epoch_ts age_sec max_sec
  ts_line="$(grep -E '^- @timestamp:' "$file" | head -n 1 || true)"
  ts="${ts_line#- @timestamp: }"

  if [[ -z "$ts" || "$ts" == "$ts_line" ]]; then
    set_result_fail "$file" "missing @timestamp"
    append_line "$file" "- freshness: FAIL (missing @timestamp)"
    return 1
  fi

  epoch_now="$(date -u +%s)"
  epoch_ts="$(date -u -d "$ts" +%s 2>/dev/null || echo "")"
  if [[ -z "$epoch_ts" ]]; then
    set_result_fail "$file" "unparseable @timestamp"
    append_line "$file" "- freshness: FAIL (unparseable @timestamp)"
    append_line "$file" "- observed.@timestamp: $ts"
    return 1
  fi

  age_sec=$(( epoch_now - epoch_ts ))
  max_sec=$(( max_hours * 3600 ))

  if (( age_sec > max_sec )); then
    set_result_fail "$file" "stale >${max_hours}h"
    append_line "$file" "- freshness: FAIL (age_seconds=${age_sec}, threshold_seconds=${max_sec})"
    return 1
  fi

  append_line "$file" "- freshness: PASS (age_seconds=${age_sec}, threshold_seconds=${max_sec})"
  return 0
}

enforce_freshness_minutes() {
  local file="$1"
  local max_min="$2"
  local ts_line ts epoch_now epoch_ts age_sec max_sec
  ts_line="$(grep -E '^- @timestamp:' "$file" | head -n 1 || true)"
  ts="${ts_line#- @timestamp: }"

  if [[ -z "$ts" || "$ts" == "$ts_line" ]]; then
    set_result_fail "$file" "missing @timestamp"
    append_line "$file" "- freshness: FAIL (missing @timestamp)"
    return 1
  fi

  epoch_now="$(date -u +%s)"
  epoch_ts="$(date -u -d "$ts" +%s 2>/dev/null || echo "")"
  if [[ -z "$epoch_ts" ]]; then
    set_result_fail "$file" "unparseable @timestamp"
    append_line "$file" "- freshness: FAIL (unparseable @timestamp)"
    append_line "$file" "- observed.@timestamp: $ts"
    return 1
  fi

  age_sec=$(( epoch_now - epoch_ts ))
  max_sec=$(( max_min * 60 ))

  if (( age_sec > max_sec )); then
    set_result_fail "$file" "inactive >${max_min}m"
    append_line "$file" "- freshness: FAIL (age_seconds=${age_sec}, threshold_seconds=${max_sec})"
    return 1
  fi

  append_line "$file" "- freshness: PASS (age_seconds=${age_sec}, threshold_seconds=${max_sec})"
  return 0
}

query_to_artifact() {
  local title="$1"
  local artifact="$2"
  local payload="$3"

  local tmp http
  tmp="$(mktemp)"
  http="$(curl -sk -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" -H 'Content-Type: application/json' \
    -o "${tmp}" -w "%{http_code}" \
    "${INDEXER_URL}/${ARCHIVES_INDEX}/_search" -d "${payload}" || true)"

  {
    echo "# ${title}"
    echo
    echo "- date: ${DATE}"
    echo "- index: ${ARCHIVES_INDEX}"
    echo "- indexer: ${INDEXER_URL}"
    echo
    if [[ "${http}" != "200" ]]; then
      echo "RESULT: FAIL (indexer HTTP=${http})"
      exit 0
    fi

    python3 - "${tmp}" <<'PY'
import json,sys
j=json.load(open(sys.argv[1]))
hits=j.get("hits",{}).get("hits",[])
if not hits:
  print("RESULT: FAIL (no matching events found)")
  sys.exit(0)
src=hits[0].get("_source",{})
print("RESULT: PASS")
print(f"- @timestamp: {src.get('@timestamp')}")
agent=src.get("agent",{}) if isinstance(src.get("agent",{}),dict) else {}
dec=src.get("decoder",{}) if isinstance(src.get("decoder",{}),dict) else {}
print(f"- agent.id: {agent.get('id')}")
print(f"- agent.name: {agent.get('name')}")
print(f"- decoder.name: {dec.get('name')}")
print(f"- location: {src.get('location')}")
data=src.get("data",{})
if isinstance(data,dict):
  win=data.get("win",{}).get("system",{}) if isinstance(data.get("win",{}),dict) else {}
  if isinstance(win,dict):
    if win.get("computer") is not None: print(f"- data.win.system.computer: {win.get('computer')}")
    if win.get("channel") is not None: print(f"- data.win.system.channel: {win.get('channel')}")
PY
  } > "${artifact}"

  rm -f "${tmp}"
  grep -q '^RESULT: PASS' "${artifact}"
}

# Payloads (same index source: wazuh-archives-4.x-*)
PAY_M1="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"agent.name\":\"${AGENT}\"}}]}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"agent.id\",\"agent.name\",\"decoder.name\",\"location\"]}"

PAY_M2="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"data.win.system.computer\":\"${HOST}\"}},{\"term\":{\"data.win.system.channel\":\"Security\"}}]}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"data.win.system.computer\",\"data.win.system.channel\",\"agent.id\",\"agent.name\",\"decoder.name\",\"location\"]}"
PAY_M3="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"data.win.system.computer\":\"${HOST}\"}},{\"term\":{\"data.win.system.channel\":\"Microsoft-Windows-Sysmon/Operational\"}}]}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"data.win.system.computer\",\"data.win.system.channel\",\"agent.id\",\"agent.name\",\"decoder.name\",\"location\"]}"
PAY_M5="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"agent.name\":\"${AGENT}\"}},{\"term\":{\"decoder.name\":\"syscollector\"}}]}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"agent.id\",\"agent.name\",\"decoder.name\",\"location\"]}"
PAY_M6="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"agent.name\":\"${AGENT}\"}},{\"term\":{\"decoder.name\":\"sca\"}}]}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"agent.id\",\"agent.name\",\"decoder.name\",\"location\"]}"

FAIL=0

# M1 Agent Active (<= 15m)
if query_to_artifact "M1 — Agent active (agent.name=${AGENT})" "${M1}" "${PAY_M1}"; then
  if enforce_freshness_minutes "${M1}" "${ACTIVE_MIN_ONBOARDING}"; then M1R="PASS"; else M1R="FAIL"; FAIL=1; fi
else
  M1R="FAIL"; FAIL=1
fi

# M4 Hostname consistency (HOST vs AGENT)
{
  echo "# M4 — Hostname consistency"
  echo
  echo "- date: ${DATE}"
  echo "- observed.host (data.win.system.computer): ${HOST}"
  echo "- observed.agent (agent.name): ${AGENT}"
  echo
  if [[ -n "${HOST}" && -n "${AGENT}" && "${HOST}" == "${AGENT}" ]]; then
    echo "RESULT: PASS"
  else
    echo "RESULT: FAIL (HOST != AGENT or empty)"
  fi
} > "${M4}"
if grep -q '^RESULT: PASS' "${M4}"; then M4R="PASS"; else M4R="FAIL"; FAIL=1; fi

# M2/M3/M5/M6 + freshness <=24h
if query_to_artifact "M2 — Windows Security ingestion (host=${HOST})" "${M2}" "${PAY_M2}"; then
  if enforce_freshness_hours "${M2}" "${FRESH_HOURS_ONBOARDING}"; then M2R="PASS"; else M2R="FAIL"; FAIL=1; fi
else
  M2R="FAIL"; FAIL=1
fi

if query_to_artifact "M3 — Sysmon ingestion (host=${HOST})" "${M3}" "${PAY_M3}"; then
  if enforce_freshness_hours "${M3}" "${FRESH_HOURS_ONBOARDING}"; then M3R="PASS"; else M3R="FAIL"; FAIL=1; fi
else
  M3R="FAIL"; FAIL=1
fi

if query_to_artifact "M5 — Syscollector present (agent=${AGENT})" "${M5}" "${PAY_M5}"; then
  if enforce_freshness_hours "${M5}" "${FRESH_HOURS_ONBOARDING}"; then M5R="PASS"; else M5R="FAIL"; FAIL=1; fi
else
  M5R="FAIL"; FAIL=1
fi

if query_to_artifact "M6 — SCA present (agent=${AGENT})" "${M6}" "${PAY_M6}"; then
  if enforce_freshness_hours "${M6}" "${FRESH_HOURS_ONBOARDING}"; then M6R="PASS"; else M6R="FAIL"; FAIL=1; fi
else
  M6R="FAIL"; FAIL=1
fi

echo "SUMMARY:"
echo "- M1 Agent active     : ${M1R} -> ${M1}"
echo "- M2 Security ingest  : ${M2R} -> ${M2}"
echo "- M3 Sysmon ingest    : ${M3R} -> ${M3}"
echo "- M4 Host consistency : ${M4R} -> ${M4}"
echo "- M5 Syscollector     : ${M5R} -> ${M5}"
echo "- M6 SCA              : ${M6R} -> ${M6}"

if [[ "${FAIL}" -eq 0 ]]; then
  echo "FINAL: PASS (all MUST validations passed)"
  exit 0
fi
echo "FINAL: FAIL (one or more MUST validations failed)"
exit 1
