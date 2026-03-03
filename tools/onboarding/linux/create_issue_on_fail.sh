#!/usr/bin/env bash
set -euo pipefail

# Create a GitHub Issue for Linux onboarding gate failures (no secrets).
# Avoids spam: if an OPEN issue with same title exists, no new issue is created.

REPO="${GITHUB_REPO:-luventri/SOC}"
TITLE="${1:-}"
BODY_FILE="${2:-}"
LABELS_BASE="linux,onboarding,coverage,telemetry"

if [[ -z "${TITLE}" || -z "${BODY_FILE}" ]]; then
  echo "FAIL: usage: create_issue_on_fail.sh \"<title>\" <body_file>"
  exit 2
fi

if [[ ! -f "${BODY_FILE}" ]]; then
  echo "FAIL: body file not found: ${BODY_FILE}"
  exit 2
fi

if gh label list --repo "${REPO}" --limit 200 | awk '{print $1}' | grep -qx "data-quality"; then
  LABELS="${LABELS_BASE},data-quality"
else
  LABELS="${LABELS_BASE}"
fi

EXISTING_URL="$(gh issue list --repo "${REPO}" --state open --search "${TITLE} in:title" --json title,url --jq '.[] | select(.title=="'"${TITLE//\"/\\\"}"'") | .url' | head -n 1 || true)"
if [[ -n "${EXISTING_URL}" ]]; then
  echo "OK: issue already exists (open): ${EXISTING_URL}"
  exit 0
fi

URL="$(gh issue create --repo "${REPO}" --title "${TITLE}" --label "${LABELS}" --body-file "${BODY_FILE}")"
echo "OK: issue created ${URL}"
