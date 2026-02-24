#!/usr/bin/env bash
set -euo pipefail

# Restore APPLY (SOC): pulls remote "latest" backup and restores config + docker volumes.
# Intended for DR / new host. Can be run on a fresh soc-core after installing docker+compose.

# Safety: requires explicit confirmation
CONFIRM="${1:-}"
if [[ "${CONFIRM}" != "--i-understand-this-will-restore" ]]; then
  echo "ERROR: This script performs a restore apply."
  echo "Run: $0 --i-understand-this-will-restore"
  exit 2
fi

REPO_ROOT="/home/socadmin/soc-cases"

BACKUP_USER="socbackup"
BACKUP_HOST="192.168.242.129"
BACKUP_BASE="/srv/soc-backups"
SSH_KEY="${HOME}/.ssh/soc_backup_ed25519"
REMOTE_LATEST="${BACKUP_BASE}/latest"

# Target paths (current SOC layout)
WAZUH_BASE="/home/socadmin/wazuh-docker/single-node"
WAZUH_COMPOSE="${WAZUH_BASE}/docker-compose.yml"
WAZUH_CONFIG_DIR="${WAZUH_BASE}/config"

TS="$(date +%F_%H%M%S)"
WORK="${REPO_ROOT}/tmp/backup_restore_apply_${TS}"
mkdir -p "${WORK}"

cleanup() { echo "[*] Keeping workdir for review: ${WORK}"; }
trap cleanup EXIT

echo "[*] Pull remote latest into: ${WORK}"
rsync -a -e "ssh -i ${SSH_KEY}" "${BACKUP_USER}@${BACKUP_HOST}:${REMOTE_LATEST}/" "${WORK}/"

echo "[*] Pre-flight checks"
test -f "${WORK}/MANIFEST.txt"
test -f "${WORK}/wazuh/docker-compose.yml"
test -d "${WORK}/wazuh/config"
test -d "${WORK}/docker-volumes"

echo "[*] Restoring Wazuh compose + config to ${WAZUH_BASE}"
mkdir -p "${WAZUH_BASE}"
cp -a "${WORK}/wazuh/docker-compose.yml" "${WAZUH_COMPOSE}"
rm -rf "${WAZUH_CONFIG_DIR}"
cp -a "${WORK}/wazuh/config" "${WAZUH_CONFIG_DIR}"

echo "[*] Restoring Docker volumes from archives"
shopt -s nullglob
for tgz in "${WORK}/docker-volumes/"*.tar.gz; do
  vol="$(basename "${tgz}" .tar.gz)"
  echo "  - volume: ${vol}"
  docker volume inspect "${vol}" >/dev/null 2>&1 || docker volume create "${vol}" >/dev/null
  docker run --rm -v "${vol}:/v" -v "${WORK}/docker-volumes:/in:ro" ubuntu:24.04 \
    bash -lc "rm -rf /v/* && tar -xzf /in/${vol}.tar.gz -C /v"
done

echo "[OK] Restore APPLY completed."
echo "Next steps (manual, recommended):"
echo "  docker compose -f ${WAZUH_COMPOSE} up -d"
echo "  ./tools/platform_health.sh"
