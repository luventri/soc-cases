#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  tools/dq/network_pfsense_gate.sh [--date YYYY-MM-DD] [--minutes N] [--source-ip IP]

Defaults:
  --date      today
  --minutes   15
  --source-ip 192.168.242.131

Exit code:
  0 = PASS (MUST checks pass)
  1 = FAIL (one or more MUST checks fail)
  2 = execution/config error
USAGE
}

DATE="$(date +%F)"
MINUTES=15
SOURCE_IP="192.168.242.131"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --date) DATE="${2:-}"; shift 2 ;;
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

OUTDIR="${REPO_ROOT}/artifacts/dq/network"
mkdir -p "${OUTDIR}"
RUN_LOG="${OUTDIR}/pfsense_gate_run_${DATE}.log"
ARTIFACT="${OUTDIR}/pfsense_gate_${DATE}.md"

exec > >(tee "${RUN_LOG}") 2>&1

TMP="$(mktemp)"
PAYLOAD="$(cat <<JSON
{
  "size": 200,
  "sort": [{"@timestamp":{"order":"desc"}}],
  "_source": ["@timestamp","location","predecoder.program_name","decoder.name","full_log"],
  "query": {
    "bool": {
      "filter": [
        {"range":{"@timestamp":{"gte":"now-${MINUTES}m"}}},
        {"term":{"location.keyword":"${SOURCE_IP}"}}
      ],
      "should": [
        {"match_phrase":{"full_log":"filterlog"}},
        {"match_phrase":{"full_log":"dhcpd"}},
        {"match_phrase":{"full_log":"pfsense-test"}}
      ],
      "minimum_should_match": 1
    }
  }
}
JSON
)"

HTTP="$(curl -sS "${CURL_TLS[@]}" -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" -H 'Content-Type: application/json' \
  -o "${TMP}" -w "%{http_code}" "${INDEXER_URL}/${ARCHIVES_INDEX}/_search" -d "${PAYLOAD}" || true)"

if [[ "${HTTP}" != "200" ]]; then
  echo "FAIL: indexer query HTTP=${HTTP}"
  rm -f "${TMP}"
  exit 2
fi

python3 - "${TMP}" "${SOURCE_IP}" "${MINUTES}" "${ARTIFACT}" <<'PY'
import json,sys,re,datetime
path,source_ip,mins,artifact=sys.argv[1],sys.argv[2],int(sys.argv[3]),sys.argv[4]
j=json.load(open(path,encoding="utf-8"))
hits=((j.get("hits") or {}).get("hits") or [])
src=[h.get("_source",{}) for h in hits]

must_fail=False
warn=False

recent_count=len(src)
m1_pass=recent_count>0
if not m1_pass:
    must_fail=True

filterlog=[s for s in src if "filterlog" in (s.get("full_log",""))]
m2_pass=len(filterlog)>0
if not m2_pass:
    must_fail=True

sample=filterlog[0] if filterlog else {}
line=sample.get("full_log","")
fields_ok=False
action=proto=srcip=dstip=sport=dport="N/A"
if line:
    # pfSense filterlog CSV starts after first ': '
    parts=line.split(": ",1)
    payload=parts[1] if len(parts)==2 else ""
    f=payload.split(",")
    # Common indexes for filterlog CSV in this lab:
    # action idx 6, proto-name idx 16, srcip idx 18, dstip idx 19, srcport idx 20, dstport idx 21
    try:
        action=f[6]
        proto=f[16]
        srcip=f[18]
        dstip=f[19]
        sport=f[20]
        dport=f[21]
        ip_re=re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if ip_re.match(srcip) and ip_re.match(dstip) and sport.isdigit() and dport.isdigit():
            fields_ok=True
    except Exception:
        fields_ok=False

m3_pass=fields_ok
if not m3_pass:
    must_fail=True

dhcp_or_system=[s for s in src if ("dhcpd" in (s.get("full_log","")) or "pfsense-test" in (s.get("full_log","")))]
m4_pass=len(dhcp_or_system)>0
if not m4_pass:
    warn=True

now=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

lines=[]
lines.append("# pfSense network DQ gate")
lines.append("")
lines.append(f"- Generated (UTC): {now}")
lines.append(f"- Window: now-{mins}m .. now")
lines.append(f"- Source IP: {source_ip}")
lines.append(f"- Total matched events: {recent_count}")
lines.append("")
lines.append("## Checks")
lines.append(f"- N1 recent ingest from source ({source_ip}): {'PASS' if m1_pass else 'FAIL'}")
lines.append(f"- N2 filterlog presence: {'PASS' if m2_pass else 'FAIL'}")
lines.append(f"- N3 key fields parse (action/proto/src/dst/ports): {'PASS' if m3_pass else 'FAIL'}")
lines.append(f"- N4 dhcp/system auxiliary signal: {'PASS' if m4_pass else 'WARN'}")
lines.append("")
lines.append("## Parsed sample (filterlog)")
lines.append(f"- action: {action}")
lines.append(f"- proto: {proto}")
lines.append(f"- srcip: {srcip}")
lines.append(f"- dstip: {dstip}")
lines.append(f"- srcport: {sport}")
lines.append(f"- dstport: {dport}")
lines.append("")
lines.append("## Samples")
if src:
    for s in src[:5]:
        ts=s.get("@timestamp","?")
        loc=s.get("location","?")
        log=s.get("full_log","")
        if len(log)>180:
            log=log[:180]+"..."
        lines.append(f"- {ts} | {loc} | {log}")
else:
    lines.append("- (none)")
lines.append("")
if must_fail:
    lines.append("## Result")
    lines.append("**FAIL**")
elif warn:
    lines.append("## Result")
    lines.append("**PASS_WITH_WARN**")
else:
    lines.append("## Result")
    lines.append("**PASS**")

open(artifact,"w",encoding="utf-8").write("\n".join(lines)+"\n")

print("SUMMARY:")
print(f"- N1 recent ingest      : {'PASS' if m1_pass else 'FAIL'}")
print(f"- N2 filterlog presence : {'PASS' if m2_pass else 'FAIL'}")
print(f"- N3 key field parse    : {'PASS' if m3_pass else 'FAIL'}")
print(f"- N4 aux signal         : {'PASS' if m4_pass else 'WARN'}")
if must_fail:
    print("FINAL: FAIL")
elif warn:
    print("FINAL: PASS_WITH_WARN")
else:
    print("FINAL: PASS")
print(f"ARTIFACT: {artifact}")
PY

rm -f "${TMP}"

if grep -q '^FINAL: FAIL' "${RUN_LOG}"; then
  ISSUE_BODY="${OUTDIR}/pfsense_gate_fail_${DATE}.md"
  {
    echo "# pfSense network DQ gate — FAIL"
    echo
    echo "- date: ${DATE}"
    echo "- source_ip: ${SOURCE_IP}"
    echo "- window_minutes: ${MINUTES}"
    echo
    echo "## Artifacts"
    echo "- ${ARTIFACT}"
    echo "- ${RUN_LOG}"
    echo
    echo "## Result"
    echo "**FAIL**"
  } > "${ISSUE_BODY}"

  if command -v gh >/dev/null 2>&1; then
    REPO="${GITHUB_REPO:-luventri/SOC}"
    TITLE="pfSense network DQ gate FAIL (${SOURCE_IP}) ${DATE}"
    gh issue create --repo "${REPO}" --title "${TITLE}" --label "network,telemetry,data-quality,pfsense" --body-file "${ISSUE_BODY}" >/dev/null 2>&1 || true
  fi
  exit 1
fi

exit 0
