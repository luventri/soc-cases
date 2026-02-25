#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART_DIR="${REPO_ROOT}/artifacts/platform/secrets"
DATE_UTC="$(date -u +%F)"
OUT="${ART_DIR}/secrets_audit_${DATE_UTC}.md"

FAIL=0

mkdir -p "${ART_DIR}"

{
  echo "# Secrets audit (${DATE_UTC} UTC)"
  echo
  echo "## Scope"
  echo "- Repo: ${REPO_ROOT}"
  echo "- Secrets dir: ~/.secrets (checked permissions only; no values printed)"
  echo
  echo "## Checks"
  echo
  echo "### 1) ~/.secrets permissions"
  if ls -ld "${HOME}/.secrets"; then :; else FAIL=1; fi
  if stat -c '%A %U:%G %n' "${HOME}/.secrets/mini-soc.env"; then :; else FAIL=1; fi
  echo

  echo "### 2) Disallowed secret-like files inside repo (working tree scan)"
  if find "${REPO_ROOT}" -not -path "${REPO_ROOT}/.git/*" -not -path "${REPO_ROOT}/artifacts/*" -not -path "${REPO_ROOT}/tmp/*" \
    \( -name "*.env" -o -name ".env" -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" -o -name "id_rsa" -o -name "id_ed25519" \) \
    -print | sed "s|^${REPO_ROOT}/||" | sort | awk 'BEGIN{c=0} {print "- FOUND: "$0; c++} END{if(c==0) print "- OK: none found"}'
  then :; else FAIL=1; fi

  if find "${REPO_ROOT}" -not -path "${REPO_ROOT}/.git/*" -not -path "${REPO_ROOT}/artifacts/*" -not -path "${REPO_ROOT}/tmp/*" \
    \( -name "*.env" -o -name ".env" -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" -o -name "id_rsa" -o -name "id_ed25519" \) \
    -print -quit | grep -q .
  then FAIL=1; fi
  echo

  echo "### 3) Git tracked files that should never be committed"
  if git -C "${REPO_ROOT}" ls-files | grep -E '\.env($|\.)|(^|/)\.env|secrets|secret|\.key$|\.pem$|\.p12$|\.pfx$|(^|/)id_rsa$|(^|/)id_ed25519$|token|apikey|api_key' \
    | sed 's/^/- TRACKED: /'
  then FAIL=1
  else
    echo "- OK: none tracked"
  fi
  echo

  echo "## Result"
  if [ "${FAIL}" -eq 0 ]; then echo "**PASS**"; else echo "**FAIL**"; fi
} > "${OUT}"

echo "OK: wrote evidence ${OUT}"
tail -n 6 "${OUT}"

exit "${FAIL}"
