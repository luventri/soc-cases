#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  tools/onboarding/network/pfsense_ingest_check.sh [--minutes N] [--source-ip IP]

Defaults:
  --minutes   15
  --source-ip 192.168.242.131

Exit code:
  0 = PASS (events found)
  1 = FAIL (no events found)
  2 = execution/config error
USAGE
}

MINUTES=15
SOURCE_IP="192.168.242.131"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --minutes) MINUTES="${2:-}"; shift 2 ;;
    --source-ip) SOURCE_IP="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "FAIL: unknown arg: $1"; usage; exit 2 ;;
  esac
done

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
  echo "FAIL: missing WAZUH_INDEXER_USER/WAZUH_INDEXER_PASS"
  exit 2
fi

INDEXER_HOST="${OPS_INDEXER_HOSTNAME:-wazuh.indexer}"
INDEXER_ADDR="${OPS_INDEXER_ADDR:-127.0.0.1}"
INDEXER_URL="${OPS_INDEXER_URL:-https://${INDEXER_HOST}:9200}"
INDEXER_CA="${OPS_INDEXER_CA:-/home/socadmin/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem}"
ARCHIVES_INDEX="${OPS_ARCHIVES_INDEX:-wazuh-archives-4.x-*}"

if [[ ! -f "${INDEXER_CA}" ]]; then
  echo "FAIL: missing indexer CA file: ${INDEXER_CA}"
  exit 2
fi

CURL_TLS=(--cacert "${INDEXER_CA}")
if [[ "${INDEXER_URL}" == "https://${INDEXER_HOST}:9200"* ]]; then
  CURL_TLS+=(--resolve "${INDEXER_HOST}:9200:${INDEXER_ADDR}")
fi

PAYLOAD="$(cat <<JSON
{
  "size": 30,
  "sort": [{"@timestamp":{"order":"desc"}}],
  "_source": ["@timestamp","location","predecoder.program_name","decoder.name","full_log"],
  "query": {
    "bool": {
      "filter": [{"range":{"@timestamp":{"gte":"now-${MINUTES}m"}}}],
      "should": [
        {"term":{"location.keyword":"${SOURCE_IP}"}},
        {"match_phrase":{"full_log":"filterlog"}},
        {"match_phrase":{"full_log":"dhcpd"}}
      ],
      "minimum_should_match": 1
    }
  }
}
JSON
)"

TMP="$(mktemp)"
HTTP="$(curl -sS "${CURL_TLS[@]}" -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" -H 'Content-Type: application/json' \
  -o "${TMP}" -w "%{http_code}" "${INDEXER_URL}/${ARCHIVES_INDEX}/_search" -d "${PAYLOAD}" || true)"

if [[ "${HTTP}" != "200" ]]; then
  echo "FAIL: indexer query HTTP=${HTTP}"
  rm -f "${TMP}"
  exit 2
fi

RESULT="$(python3 - "${TMP}" "${SOURCE_IP}" "${MINUTES}" <<'PY'
import json,sys
path,src,mins=sys.argv[1],sys.argv[2],sys.argv[3]
j=json.load(open(path,encoding="utf-8"))
hits=((j.get("hits") or {}).get("hits") or [])
total=((j.get("hits") or {}).get("total") or {}).get("value",0)
print(f"Window: last {mins}m")
print(f"Source IP target: {src}")
print(f"Matched events: {total}")
if hits:
    print("Top samples:")
    for h in hits[:5]:
        s=h.get("_source",{})
        ts=s.get("@timestamp","?")
        loc=s.get("location","?")
        log=(s.get("full_log","") or "").strip()
        if len(log)>140:
            log=log[:140]+"..."
        print(f"- {ts} | {loc} | {log}")
    print("RESULT=PASS")
else:
    print("RESULT=FAIL")
PY
)"

echo "${RESULT}"
rm -f "${TMP}"

if grep -q "RESULT=PASS" <<<"${RESULT}"; then
  exit 0
fi
exit 1
