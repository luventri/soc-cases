#!/usr/bin/env bash
set -euo pipefail

# Coverage report (last 24h) - Wazuh Indexer (wazuh-archives-4.x-*)
# - No CWD dependency: resolves repo root from script path.
# - No secrets printed: uses ~/.secrets/mini-soc.env and does not echo creds.
# - Output: artifacts/telemetry/coverage/coverage_24h_YYYY-MM-DD.md

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DATE="${1:-$(date +%F)}"
OUTDIR="${REPO_ROOT}/artifacts/telemetry/coverage"
OUT="${OUTDIR}/coverage_24h_${DATE}.md"

SECRETS_FILE="${HOME}/.secrets/mini-soc.env"
INDEXER_URL="${OPS_INDEXER_URL:-https://127.0.0.1:9200}"
ARCHIVES_INDEX="${OPS_ARCHIVES_INDEX:-wazuh-archives-4.x-*}"

mkdir -p "${OUTDIR}"

if [[ -f "${SECRETS_FILE}" ]]; then
  # shellcheck disable=SC1090
  set -a
  source "${SECRETS_FILE}"
  set +a
fi

if [[ -z "${WAZUH_INDEXER_USER:-}" || -z "${WAZUH_INDEXER_PASS:-}" ]]; then
  echo "FAIL: missing WAZUH_INDEXER_USER/WAZUH_INDEXER_PASS in environment or ${SECRETS_FILE}"
  exit 2
fi

TMP="$(mktemp)"
HTTP="$(curl -sk -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" -H 'Content-Type: application/json' \
  -o "${TMP}" -w "%{http_code}" \
  "${INDEXER_URL}/${ARCHIVES_INDEX}/_search" \
  -d '{"size":0,"query":{"range":{"@timestamp":{"gte":"now-24h"}}},"aggs":{"channels":{"terms":{"field":"data.win.system.channel","size":50}},"hosts":{"terms":{"field":"data.win.system.computer","size":50}},"agents":{"terms":{"field":"agent.name","size":50}}}}' || true)"

if [[ "${HTTP}" != "200" ]]; then
  echo "FAIL: indexer query HTTP=${HTTP}"
  rm -f "${TMP}"
  exit 2
fi

python3 - "${TMP}" "${OUT}" <<'PY'
import json,sys,datetime
j=json.load(open(sys.argv[1]))
out=sys.argv[2]
total=j.get("hits",{}).get("total",{})
val=total.get("value",0) if isinstance(total,dict) else total
ag=j.get("aggregations",{})
def buckets(name):
  b=ag.get(name,{}).get("buckets",[])
  return [(x.get("key"), x.get("doc_count")) for x in b if x.get("key") is not None]

now=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
lines=[]
lines.append("# Coverage report — last 24h")
lines.append("")
lines.append(f"- Generated (UTC): {now}")
lines.append(f"- Source: wazuh-archives-4.x-* (Indexer)")
lines.append(f"- Window: now-24h .. now")
lines.append(f"- Total events (all): {val}")
lines.append("")
lines.append("## Top agents (agent.name)")
ba=buckets("agents")
lines += [f"- {k}: {c}" for k,c in ba] if ba else ["- (none)"]
lines.append("")
lines.append("## Top hosts (data.win.system.computer)")
bh=buckets("hosts")
lines += [f"- {k}: {c}" for k,c in bh] if bh else ["- (none)"]
lines.append("")
lines.append("## Top Windows channels (data.win.system.channel)")
bc=buckets("channels")
lines += [f"- {k}: {c}" for k,c in bc] if bc else ["- (none)"]
lines.append("")
lines.append("## Result")
lines.append("**PASS** (report generated).")
open(out,"w",encoding="utf-8").write("\n".join(lines)+ "\n")
print(f"OK: wrote {out}")
PY

rm -f "${TMP}"
echo "OK: coverage report generated (no secrets printed)"
