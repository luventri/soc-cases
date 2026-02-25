#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ART_DIR="$REPO_ROOT/artifacts/platform/access-control"
mkdir -p "$ART_DIR"

TS="$(date +%F_%H%M%S)"
OUT="$ART_DIR/rbac-users-verify-${TS}.log"
RAW_DIR="$ART_DIR/raw-${TS}"
mkdir -p "$RAW_DIR"

INDEXER_CONTAINER="${INDEXER_CONTAINER:-single-node-wazuh.indexer-1}"
SECRETS_FILE="${SECRETS_FILE:-$HOME/.secrets/mini-soc.env}"
USERS_YML="${USERS_YML:-$REPO_ROOT/tools/access-control/users.yml}"
DASHBOARDS_URL="${DASHBOARDS_URL:-https://192.168.242.128}"
OSD_VERSION="${OSD_VERSION:-2.13.0}"

# --- PASS/FAIL state ---
PASS=true
FAIL_REASONS=()
fail(){ PASS=false; FAIL_REASONS+=("$*"); }

# Post-run assertions on the generated OUT log (no manual edits required)
assert_all_http_eq(){
  local label="$1" expect="$2"
  awk -v L="$label" -v E="$expect" '$0 ~ (L " HTTP=") { if ($NF != ("HTTP=" E)) bad=1 } END { exit bad }' "$OUT" || fail "${label}: expected ALL HTTP=${expect}"
}
assert_all_http_in(){
  local label="$1" allowed_re="$2"
  awk -v L="$label" -v R="$allowed_re" '$0 ~ (L " HTTP=") { if ($NF !~ ("HTTP=" R "$")) bad=1 } END { exit bad }' "$OUT" || fail "${label}: expected ALL HTTP in ${allowed_re}"
}

log() { printf '%s\n' "$*" | tee -a "$OUT"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 1; }; }

need_cmd curl
need_cmd python3
need_cmd awk
need_cmd grep
need_cmd sed

DOCKER="docker"
if ! docker ps >/dev/null 2>&1; then
  DOCKER="sudo docker"
fi
if [[ "$DOCKER" == "sudo docker" ]]; then
  sudo -v
fi

admin_curl_to_file() {
  local url="$1"
  local outfile="$2"
  $DOCKER exec -i "$INDEXER_CONTAINER" sh -lc \
"curl -sk \
  --cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  --cert /usr/share/wazuh-indexer/certs/admin.pem \
  --key  /usr/share/wazuh-indexer/certs/admin-key.pem \
  '$url'" > "$outfile" 2>/dev/null || true
}

ensure_json_or_die() {
  local f="$1"
  local label="$2"
  if [ ! -s "$f" ]; then
    log "ERROR: $label is empty (file: $f). Check docker/container/certs."
    exit 1
  fi
  if ! python3 - <<PY >/dev/null 2>&1
import json
json.load(open("$f","r",encoding="utf-8"))
PY
  then
    log "ERROR: $label is not valid JSON (file: $f). First lines:"
    sed -n '1,60p' "$f" | tee -a "$OUT"
    exit 1
  fi
}

get_secret() {
  local var="$1"
  [ -f "$SECRETS_FILE" ] || return 0
  grep -E "^${var}=" "$SECRETS_FILE" | head -n1 | cut -d= -f2- || true
}

list_mapped_users_from_users_yml() {
  # users.yml contains:
  # credential_map:
  #   - username: analyst
  #     pass_env: ANALYST_PASS
  awk '
    $1=="-" && $2=="username:" {u=$3}
    $1=="pass_env:" {p=$2; if(u!="" && p!="") print u" "p; u=""; p=""}
  ' "$USERS_YML" 2>/dev/null || true
}

pick_sample_wazuh_index() {
  $DOCKER exec -i "$INDEXER_CONTAINER" sh -lc \
"curl -sk \
  --cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  --cert /usr/share/wazuh-indexer/certs/admin.pem \
  --key  /usr/share/wazuh-indexer/certs/admin-key.pem \
  'https://127.0.0.1:9200/_cat/indices/wazuh-alerts-*?h=index&expand_wildcards=all'" \
  | tr -d '\r' | head -n 1 || true
}

log "=== RBAC USERS VERIFY ==="
log "DATE: $(date -Is)"
log "REPO: $REPO_ROOT"
log "INDEXER_CONTAINER: $INDEXER_CONTAINER"
log "DASHBOARDS_URL: $DASHBOARDS_URL"
log "DOCKER_CMD: $DOCKER"
log "OUT: $OUT"
log ""

log "=== GLOBAL AUDIT (admin cert, no passwords) ==="
admin_curl_to_file "https://127.0.0.1:9200/_plugins/_security/api/internalusers" "$RAW_DIR/internalusers.json"
ensure_json_or_die "$RAW_DIR/internalusers.json" "internalusers"
log "saved: $RAW_DIR/internalusers.json"

admin_curl_to_file "https://127.0.0.1:9200/_plugins/_security/api/rolesmapping" "$RAW_DIR/rolesmapping.json"
ensure_json_or_die "$RAW_DIR/rolesmapping.json" "rolesmapping"
log "saved: $RAW_DIR/rolesmapping.json"

admin_curl_to_file "https://127.0.0.1:9200/_plugins/_security/api/roles" "$RAW_DIR/roles.json"
ensure_json_or_die "$RAW_DIR/roles.json" "roles"
log "saved: $RAW_DIR/roles.json"
log ""

log "=== USERS + EFFECTIVE ROLES SUMMARY (computed) ==="
python3 - <<PY | tee -a "$OUT"
import json, re

internalusers = json.load(open("$RAW_DIR/internalusers.json","r",encoding="utf-8"))
rolesmapping = json.load(open("$RAW_DIR/rolesmapping.json","r",encoding="utf-8"))
roles = json.load(open("$RAW_DIR/roles.json","r",encoding="utf-8"))

def safe_list(x):
    return x if isinstance(x,list) else []

# Build mapping: role -> users/backend_roles
rm_users = {}
rm_backend = {}
for role, v in rolesmapping.items():
    rm_users[role] = set(safe_list(v.get("users",[])))
    rm_backend[role] = set(safe_list(v.get("backend_roles",[])))

# For each role, precompute risk flags from roles.yml content
def role_risk(role_name, role_obj):
    risks = set()
    # index perms
    for ip in role_obj.get("index_permissions",[]) or []:
        for act in ip.get("allowed_actions",[]) or []:
            a = str(act)
            if "write" in a or "delete" in a or "create" in a or "update" in a:
                risks.add("INDEX_WRITE")
    # cluster perms
    for cp in role_obj.get("cluster_permissions",[]) or []:
        c = str(cp)
        if "cluster:admin" in c or "cluster:monitor" in c:
            # monitor is not necessarily bad, but highlight admin
            if "cluster:admin" in c:
                risks.add("CLUSTER_ADMIN")
        if "opensearch/security" in c or "_plugins/_security" in c:
            risks.add("SECURITY_API")
    # tenant perms
    for tp in role_obj.get("tenant_permissions",[]) or []:
        for act in tp.get("allowed_actions",[]) or []:
            a = str(act)
            if "all" in a and "read" not in a:
                risks.add("TENANT_WRITE")
    return risks

role_risks = {r: role_risk(r, obj) for r, obj in roles.items()}

# Compute effective roles for each user based on:
# 1) explicit rolesmapping.users contains user
# 2) rolesmapping.backend_roles intersects internalusers[user].backend_roles
def effective_roles_for_user(username):
    uobj = internalusers.get(username, {}) or {}
    backend_roles = set((uobj.get("backend_roles") or []))
    eff = set()
    for role in rolesmapping.keys():
        if username in rm_users.get(role,set()):
            eff.add(role)
        if backend_roles and (backend_roles & rm_backend.get(role,set())):
            eff.add(role)
    return backend_roles, eff

# Heuristic: classify "analyst-like" if any effective role contains 'analyst' or 'readonly' OR backend role kibana_read_only
def is_analyst_like(username, backend_roles, eff_roles):
    if "kibana_read_only" in backend_roles:
        return True
    for r in eff_roles:
        rn = r.lower()
        if "analyst" in rn or "readonly" in rn:
            return True
    return False

users = sorted(internalusers.keys())

print("username\tbackend_roles\teffective_roles\tclass\trisk_flags")
for u in users:
    backend, eff = effective_roles_for_user(u)
    flags = set()
    for r in eff:
        flags |= role_risks.get(r,set())
    cls = "analyst_like" if is_analyst_like(u, backend, eff) else "other"
    print(f"{u}\t{','.join(sorted(backend))}\t{','.join(sorted(eff))}\t{cls}\t{','.join(sorted(flags)) if flags else '-'}")
PY
log ""

log "=== CACHE FLUSH (admin cert) ==="
$DOCKER exec -i "$INDEXER_CONTAINER" sh -lc \
"curl -sk \
  --cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  --cert /usr/share/wazuh-indexer/certs/admin.pem \
  --key  /usr/share/wazuh-indexer/certs/admin-key.pem \
  -XDELETE 'https://127.0.0.1:9200/_plugins/_security/api/cache'" \
| tee -a "$OUT"
log ""

SAMPLE_IDX="$(pick_sample_wazuh_index)"
log "=== SAMPLE WAZUH INDEX ==="
log "sample_wazuh_index=${SAMPLE_IDX:-<none found>}"
log ""

log "=== FUNCTIONAL TESTS (ONLY for users with credentials in users.yml) ==="
if [ ! -f "$USERS_YML" ]; then
  log "NOTE: users.yml not found; SKIP functional tests."
  log "OK: evidence saved to $OUT"
  exit 0
fi

MAPPED="$(list_mapped_users_from_users_yml || true)"
if [ -z "${MAPPED}" ]; then
  log "NOTE: No credential_map entries found in users.yml; SKIP functional tests."
  log "OK: evidence saved to $OUT"
  exit 0
fi

while read -r USER PASS_ENV; do
  [ -n "$USER" ] || continue
  [ -n "$PASS_ENV" ] || continue

  USER_PASS="$(get_secret "$PASS_ENV")"
  log ""
  log "---- USER FUNCTIONAL: $USER ----"
  log "pass_env: $PASS_ENV"

  if [ -z "$USER_PASS" ]; then
    log "SKIP: secret $PASS_ENV not found in $SECRETS_FILE"
    continue
  fi

  log "[F1] authinfo (indexer) -> should be 200"
  curl -sk -u "${USER}:${USER_PASS}" "https://127.0.0.1:9200/_plugins/_security/authinfo" \
    | tee "$RAW_DIR/authinfo-${USER}.json" >/dev/null
  log "saved: $RAW_DIR/authinfo-${USER}.json"

  log "[F2] dashboards saved_objects/_find -> expected 200 for analyst"
  curl -sk -u "${USER}:${USER_PASS}" -H "osd-xsrf: true" -H "osd-version: ${OSD_VERSION}" \
    -o /dev/null -w "saved_objects_find HTTP=%{http_code}\n" \
    "${DASHBOARDS_URL}/api/saved_objects/_find?type=index-pattern&per_page=1" \
    | tee -a "$OUT"

  if [ -n "${SAMPLE_IDX}" ]; then
    log "[F3] wazuh index search -> expected 200 for analyst"
    curl -sk -u "${USER}:${USER_PASS}" -H 'Content-Type: application/json' \
      -d '{"size":0,"query":{"match_all":{}}}' \
      -o /dev/null -w "wazuh_search HTTP=%{http_code}\n" \
      "https://127.0.0.1:9200/${SAMPLE_IDX}/_search" \
      | tee -a "$OUT"

    log "[F4] NEGATIVE: write to wazuh index -> expected 403 for analyst"
    curl -sk -u "${USER}:${USER_PASS}" -H 'Content-Type: application/json' \
      -d "{\"rbac_test\":\"deny_write\",\"user\":\"${USER}\",\"ts\":\"$(date -Is)\"}" \
      -o "$RAW_DIR/deny_write-${USER}.json" -w "wazuh_write HTTP=%{http_code}\n" \
      "https://127.0.0.1:9200/${SAMPLE_IDX}/_doc/rbac-deny-write-test-${USER}-${TS}" \
      | tee -a "$OUT"
  else
    log "[F3/F4] SKIP: no wazuh-alerts-* index found"
  fi

  log "[F5] NEGATIVE: Security API -> expected 403 for analyst"
  curl -sk -u "${USER}:${USER_PASS}" -o /dev/null -w "security_api_rolesmapping HTTP=%{http_code}\n" \
    "https://127.0.0.1:9200/_plugins/_security/api/rolesmapping" | tee -a "$OUT"
  curl -sk -u "${USER}:${USER_PASS}" -o /dev/null -w "security_api_roles HTTP=%{http_code}\n" \
    "https://127.0.0.1:9200/_plugins/_security/api/roles" | tee -a "$OUT"

  log "[F6] NEGATIVE: create saved_object -> expected 401/403 for analyst"
  curl -sk -u "${USER}:${USER_PASS}" \
    -H "osd-xsrf: true" -H "osd-version: ${OSD_VERSION}" \
    -H "Content-Type: application/json" \
    -o "$RAW_DIR/deny_savedobject_create-${USER}.json" \
    -w "savedobject_create HTTP=%{http_code}\n" \
    -XPOST "${DASHBOARDS_URL}/api/saved_objects/index-pattern/rbac-deny-create-${USER}-${TS}" \
    -d "{\"attributes\":{\"title\":\"rbac-deny-create-${USER}-${TS}\",\"timeFieldName\":\"timestamp\"}}" \
    | tee -a "$OUT"

done <<< "$MAPPED"

log ""
# --- Assertions (only if functional tests ran and emitted the labels) ---
# If a label is not present in OUT, we do not assert it (keeps script usable when tests are skipped).
if grep -q "saved_objects_find HTTP=" "$OUT"; then assert_all_http_eq "saved_objects_find" "200"; fi
if grep -q "wazuh_write HTTP=" "$OUT"; then assert_all_http_eq "wazuh_write" "403"; fi
if grep -q "security_api_rolesmapping HTTP=" "$OUT"; then assert_all_http_eq "security_api_rolesmapping" "403"; fi
if grep -q "security_api_roles HTTP=" "$OUT"; then assert_all_http_eq "security_api_roles" "403"; fi
if grep -q "savedobject_create HTTP=" "$OUT"; then assert_all_http_in "savedobject_create" "(401|403)"; fi

if [ "${PASS}" = "true" ]; then
  log "=== RESULT: PASS ==="
  log "EVIDENCE_LOG: $OUT"
  log "RAW_DIR: $RAW_DIR"
  exit 0
else
  log "=== RESULT: FAIL ==="
  for r in "${FAIL_REASONS[@]}"; do log "FAIL_REASON: $r"; done
  log "EVIDENCE_LOG: $OUT"
  log "RAW_DIR: $RAW_DIR"
  exit 1
fi

# STDOUT_SUMMARY_MARKER
# Always print a short summary to stdout for operator feedback
if [ -n "${OUT:-}" ]; then
  echo "VERIFY_DONE: $(date -Is)"
  echo "EVIDENCE_LOG: $OUT"
  echo "RAW_DIR: $RAW_DIR"
fi
