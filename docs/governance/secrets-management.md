# Secrets management (home SOC)

## Scope
This document defines how secrets/tokens are handled in this repository so they stay **outside Git** and are loaded safely at runtime.

## Standard location and conventions

### Location
- Secrets directory: `~/.secrets/`
  - Required permissions:
    - directory: `0700`
    - files: `0600`

### Standard secrets file
- File: `~/.secrets/mini-soc.env`
- Format: `KEY=VALUE` (one per line)
- The repository must never contain secret values.

### Loading secrets
- Shell scripts load secrets with:
  - `set -a && source ~/.secrets/mini-soc.env && set +a`
- YAML mappings reference secrets by environment variable name using `pass_env` (no passwords stored in repo):
  - See: `tools/access-control/users.yml`

## Secret inventory (names only)

| Secret name | Used by | Where referenced |
|---|---|---|
| `ANALYST_PASS` | Wazuh / OpenSearch Security user password for the **Analyst** role used in dashboard | `tools/access-control/users.yml`, `tools/access-control/verify-users.sh` |
| `LUCIANO_VENTRICE_PASS` | Wazuh / OpenSearch Security user password for additional **Analyst-equivalent** user | `tools/access-control/users.yml`, `docs/governance/access-control.md` |
| `WAZUH_INDEXER_USER` | OpenSearch/Indexer basic auth username for platform health checks | `tools/platform_health.sh` |
| `WAZUH_INDEXER_PASS` | OpenSearch/Indexer basic auth password for platform health checks | `tools/platform_health.sh` |

Notes:
- This project treats Linux users (e.g., `socadmin`) and Wazuh/OpenSearch users as different identities.
- Any new user password must be added only as a **new env var name** in `~/.secrets/mini-soc.env` and referenced via `pass_env` in repo YAML.

## Rotation and revocation (minimum)

### Rotation (minimum)
- Rotate secrets when:
  - a collaborator changes role/leaves,
  - a token/password may have been exposed,
  - or as a routine baseline (e.g., quarterly).
- Rotation steps (high level):
  1. Create the new secret **outside the repo** and update `~/.secrets/mini-soc.env` (keep file mode `0600`).
  2. Apply the change in the relevant platform/user management procedure (e.g., OpenSearch Security internal users).
  3. Re-run verification scripts that rely on the secret (e.g., `tools/access-control/verify-users.sh`, `tools/platform_health.sh`).
  4. Revoke/disable the previous credential in the platform (or remove the old env var name if no longer needed).

### Revocation (minimum)
- If exposure is suspected:
  - rotate immediately,
  - invalidate old tokens/passwords in the platform,
  - and run the secrets audit control (see below) before committing any new evidence.

## Do not (anti-leak rules)
- Do not store secrets in:
  - Git (tracked files, commit messages),
  - GitHub Issues / PR descriptions,
  - artifacts/logs that are committed (sanitize outputs),
  - screenshots or shared snippets.
- Do not print secret values in terminal output. Prefer logging only variable names and file paths.

## Automated controls (required)
- The repository must include an automated audit that:
  - fails if it detects common secret files inside the repo,
  - and validates `~/.secrets/*` permissions (directory `0700`, files `0600`).
- Evidence of each audit run must be saved under:
  - `artifacts/platform/secrets/` (sanitized, no secret values)

