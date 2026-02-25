#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

USER="${1:-}"
if [[ -z "$USER" ]]; then
  echo "USAGE: tools/access-control/create-analyst-user.sh <username>" >&2
  exit 2
fi

# username safety
if ! [[ "$USER" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: invalid username '$USER' (allowed: A-Z a-z 0-9 . _ -)" >&2
  exit 2
fi

INDEXER_CONTAINER="${INDEXER_CONTAINER:-single-node-wazuh.indexer-1}"
SECRETS_FILE="${SECRETS_FILE:-$HOME/.secrets/mini-soc.env}"
USERS_YML="${USERS_YML:-$REPO_ROOT/tools/access-control/users.yml}"

ART_DIR="$REPO_ROOT/artifacts/platform/access-control"
mkdir -p "$ART_DIR"
TS="$(date +%F_%H%M%S)"
OUT="$ART_DIR/rbac-create-analyst-${TS}.log"
RAW_DIR="$ART_DIR/raw-create-${TS}"
mkdir -p "$RAW_DIR"

log(){ printf '%s\n' "$*" | tee -a "$OUT"; }

PASS_OK=true
FAIL_REASONS=()
fail(){ PASS_OK=false; FAIL_REASONS+=("$*"); }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 1; }; }
need_cmd curl; need_cmd python3; need_cmd awk; need_cmd sed; need_cmd grep; need_cmd tee

DOCKER="docker"
if ! docker ps >/dev/null 2>&1; then DOCKER="sudo docker"; fi
if [[ "$DOCKER" == "sudo docker" ]]; then sudo -v; fi

PASS_ENV="$(python3 - "$USER" <<'PY'
import re,sys
u=sys.argv[1]
print(re.sub(r'[^A-Za-z0-9]+','_',u).strip('_').upper() + "_PASS")
PY
)"

mkdir -p "$(dirname "$SECRETS_FILE")"
touch "$SECRETS_FILE"
chmod 600 "$SECRETS_FILE" 2>/dev/null || true

get_secret(){ local var="$1"; grep -E "^${var}=" "$SECRETS_FILE" | head -n1 | cut -d= -f2- || true; }
set_secret(){
  local var="$1" val="$2"
  if grep -qE "^${var}=" "$SECRETS_FILE"; then
    local esc; esc="$(printf '%s' "$val" | sed -e 's/[\/&]/\\&/g')"
    sed -i "s/^${var}=.*/${var}=${esc}/" "$SECRETS_FILE"
  else
    printf '%s=%s\n' "$var" "$val" >> "$SECRETS_FILE"
  fi
}

USER_PASS="$(get_secret "$PASS_ENV")"
if [[ -z "$USER_PASS" ]]; then
  USER_PASS="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)"
  set_secret "$PASS_ENV" "$USER_PASS"
fi

log "=== CREATE ANALYST USER (persistent, clone perms from 'analyst') ==="
log "DATE: $(date -Is)"
log "USER: $USER"
log "PASS_ENV: $PASS_ENV (stored in $SECRETS_FILE; not in git)"
log "INDEXER_CONTAINER: $INDEXER_CONTAINER"
log "OUT: $OUT"
log "RAW_DIR: $RAW_DIR"
log ""

# Read backend_roles from existing internal user "analyst" (admin cert). Fallback to known-good roles.
ANALYST_JSON="$RAW_DIR/internaluser-analyst.json"
$DOCKER exec -i "$INDEXER_CONTAINER" sh -lc \
"curl -sk --cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  --cert /usr/share/wazuh-indexer/certs/admin.pem \
  --key  /usr/share/wazuh-indexer/certs/admin-key.pem \
  https://127.0.0.1:9200/_plugins/_security/api/internalusers/analyst" \
> "$ANALYST_JSON" 2>/dev/null || true

BACKEND_ROLES="$(python3 - <<PY
import json
p="$ANALYST_JSON"
try:
  data=json.load(open(p,"r",encoding="utf-8"))
  roles=data.get("analyst",{}).get("backend_roles",[])
  if isinstance(roles,list) and roles:
    print(",".join(roles))
  else:
    raise Exception("empty")
except Exception:
  print("kibana_user,kibana_read_only,readall")
PY
)"

log "backend_roles_template: $BACKEND_ROLES"
log "saved: $ANALYST_JSON"
log ""

# Evidence payload (redacted password)
PAYLOAD_FILE="$RAW_DIR/payload-${USER}.json"
python3 - "$BACKEND_ROLES" <<'PY' > "$PAYLOAD_FILE"
import json,sys
roles=sys.argv[1].split(",") if sys.argv[1] else []
print(json.dumps({"password":"<redacted>","backend_roles":roles,"attributes":{}}))
PY
log "saved: $PAYLOAD_FILE"
log ""

log "-- hash generation (inside container) --"
HASH="$($DOCKER exec -i "$INDEXER_CONTAINER" sh -lc \
"/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p '$USER_PASS' 2>/dev/null | tail -n 1" \
| tr -d '\r' || true)"

if [[ -z "$HASH" ]]; then
  fail "hash_generation: empty hash output (hash.sh failed?)"
else
  log "hash: generated (not printed)"
fi
log ""

log "-- internal_users.yml upsert (no Security API; persists across securityadmin) --"
# Avoid quote hell: run a small script inside the container via stdin (sh -s)
$DOCKER exec -i -e U="$USER" -e H="$HASH" -e BR="$BACKEND_ROLES" "$INDEXER_CONTAINER" sh -s <<'SH'
set -e
F="/usr/share/wazuh-indexer/opensearch-security/internal_users.yml"
cp -a "$F" "${F}.bak.$(date +%F_%H%M%S)"

cat > /tmp/rm_user.awk <<'AWK'
BEGIN{skip=0}
# remove top-level block by username passed as -v u=...
$0 ~ ("^"u":[[:space:]]*$") {skip=1; next}
skip==1 && $0 ~ "^[^[:space:]].*:" {skip=0}
skip==0 {print}
AWK

awk -v u="$U" -f /tmp/rm_user.awk "$F" > "${F}.tmp"
cat "${F}.tmp" > "$F"
rm -f "${F}.tmp"

{
  echo ""
  echo "$U:"
  echo "  hash: \"$H\""
  echo "  reserved: false"
  echo "  backend_roles:"
  IFS=","; for r in $BR; do
    echo "    - \"$r\""
  done
  echo "  description: \"Analyst (RO) created by create-analyst-user.sh\""
} >> "$F"
SH

log "internal_users_yml_upsert: OK"
log ""

log "-- apply security config (securityadmin.sh) --"
SEC_OUT="$RAW_DIR/securityadmin.txt"
$DOCKER exec -i "$INDEXER_CONTAINER" sh -lc \
"/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /usr/share/wazuh-indexer/opensearch-security/ \
  -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  -cert  /usr/share/wazuh-indexer/certs/admin.pem \
  -key   /usr/share/wazuh-indexer/certs/admin-key.pem \
  -icl -nhnv" \
| tee "$SEC_OUT" >/dev/null || true

if grep -q "Done with success" "$SEC_OUT"; then
  log "securityadmin: OK"
else
  fail "securityadmin: did not report success (see $SEC_OUT)"
fi
log "saved: $SEC_OUT"
log ""

log "-- flush security cache (admin cert) --"
CACHE_OUT="$RAW_DIR/cache_flush.txt"
$DOCKER exec -i "$INDEXER_CONTAINER" sh -lc \
"curl -sk --cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  --cert /usr/share/wazuh-indexer/certs/admin.pem \
  --key  /usr/share/wazuh-indexer/certs/admin-key.pem \
  -XDELETE https://127.0.0.1:9200/_plugins/_security/api/cache" \
| tee "$CACHE_OUT" >/dev/null || true
log "saved: $CACHE_OUT"
log ""

log "-- ensure verify-users credential_map contains this user (no password stored) --"
mkdir -p "$(dirname "$USERS_YML")"
touch "$USERS_YML"
if ! grep -q "^credential_map:" "$USERS_YML"; then
  printf '%s\n' "credential_map:" >> "$USERS_YML"
fi
if ! grep -qE "^[[:space:]]*-[[:space:]]*username:[[:space:]]*${USER}[[:space:]]*$" "$USERS_YML"; then
  printf '%s\n' "" "  - username: ${USER}" "    pass_env: ${PASS_ENV}" >> "$USERS_YML"
  log "users.yml: appended mapping for $USER -> $PASS_ENV"
else
  log "users.yml: mapping already present for $USER"
fi
log ""

if [[ "$PASS_OK" == "true" ]]; then
  log "=== RESULT: PASS ==="
  log "EVIDENCE_LOG: $OUT"
  log "RAW_DIR: $RAW_DIR"
  log "NEXT (UI): login to Wazuh Dashboard as '$USER' and confirm plugin loads."
  exit 0
else
  log "=== RESULT: FAIL ==="
  for r in "${FAIL_REASONS[@]}"; do log "FAIL_REASON: $r"; done
  log "EVIDENCE_LOG: $OUT"
  log "RAW_DIR: $RAW_DIR"
  exit 1
fi

# STDOUT_SUMMARY_MARKER_CREATE
if [ -n "${OUT:-}" ]; then
  echo "CREATE_DONE: $(date -Is)"
  echo "EVIDENCE_LOG: $OUT"
  echo "RAW_DIR: $RAW_DIR"
fi
