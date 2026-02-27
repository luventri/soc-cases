#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  tools/onboarding/windows/windows_onboarding_audit.sh --host "<HOSTNAME>" --agent "<AGENT_NAME>" [--date YYYY-MM-DD]

Required:
  --host   Hostname for M2/M3 (matches data.win.system.computer)
  --agent  Agent name for M5/M6 (matches agent.name)

Optional:
  --date   YYYY-MM-DD (default: today)

Behavior:
  - Generates 4 artifacts under artifacts/onboarding/windows/
  - Exit code 0 only if ALL 4 checks are PASS; non-zero otherwise.
  - Loads credentials from ~/.secrets/mini-soc.env (WAZUH_INDEXER_USER/WAZUH_INDEXER_PASS) without printing secrets.
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

M2="${OUTDIR}/M2_security_${DATE}.md"
M3="${OUTDIR}/M3_sysmon_${DATE}.md"
M5="${OUTDIR}/M5_syscollector_${DATE}.md"
M6="${OUTDIR}/M6_sca_${DATE}.md"

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

PAY_M2="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"data.win.system.computer\":\"${HOST}\"}},{\"term\":{\"data.win.system.channel\":\"Security\"}}]}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"data.win.system.computer\",\"data.win.system.channel\",\"agent.id\",\"agent.name\",\"decoder.name\",\"location\"]}"
PAY_M3="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"data.win.system.computer\":\"${HOST}\"}},{\"term\":{\"data.win.system.channel\":\"Microsoft-Windows-Sysmon/Operational\"}}]}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"data.win.system.computer\",\"data.win.system.channel\",\"agent.id\",\"agent.name\",\"decoder.name\",\"location\"]}"
PAY_M5="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"agent.name\":\"${AGENT}\"}},{\"term\":{\"decoder.name\":\"syscollector\"}}]}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"agent.id\",\"agent.name\",\"decoder.name\",\"location\"]}"
PAY_M6="{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"agent.name\":\"${AGENT}\"}},{\"term\":{\"decoder.name\":\"sca\"}}]}},\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"_source\":[\"@timestamp\",\"agent.id\",\"agent.name\",\"decoder.name\",\"location\"]}"

FAIL=0
if query_to_artifact "M2 — Windows Security ingestion (${HOST})" "${M2}" "${PAY_M2}"; then M2R="PASS"; else M2R="FAIL"; FAIL=1; fi
if query_to_artifact "M3 — Sysmon ingestion (${HOST})" "${M3}" "${PAY_M3}"; then M3R="PASS"; else M3R="FAIL"; FAIL=1; fi
if query_to_artifact "M5 — Syscollector present (${AGENT})" "${M5}" "${PAY_M5}"; then M5R="PASS"; else M5R="FAIL"; FAIL=1; fi
if query_to_artifact "M6 — SCA present (${AGENT})" "${M6}" "${PAY_M6}"; then M6R="PASS"; else M6R="FAIL"; FAIL=1; fi

echo "SUMMARY:"
echo "- M2 Security: ${M2R} -> ${M2}"
echo "- M3 Sysmon  : ${M3R} -> ${M3}"
echo "- M5 Syscoll : ${M5R} -> ${M5}"
echo "- M6 SCA     : ${M6R} -> ${M6}"

if [[ "${FAIL}" -eq 0 ]]; then
  echo "FINAL: PASS (all validations passed)"
  exit 0
fi
echo "FINAL: FAIL (one or more validations failed)"
exit 1
