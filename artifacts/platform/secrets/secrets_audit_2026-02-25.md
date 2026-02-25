# Secrets audit (2026-02-25 UTC)

## Scope
- Repo: /home/socadmin/soc-cases
- Secrets dir: ~/.secrets (checked permissions only; no values printed)

## Checks

### 1) ~/.secrets permissions
drwx------ 2 socadmin socadmin 4096 Feb 24 11:27 /home/socadmin/.secrets
-rw------- socadmin:socadmin /home/socadmin/.secrets/mini-soc.env

### 2) Disallowed secret-like files inside repo (working tree scan)
- OK: none found

### 3) Git tracked files that should never be committed
- OK: none tracked

## Result
**PASS**
