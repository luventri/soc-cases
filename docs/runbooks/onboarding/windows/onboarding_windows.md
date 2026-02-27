# Windows Onboarding (Wazuh) — Executable & Auditable

**Document:** `docs/onboarding_windows.md`  
**Repo root (lab):** `/home/socadmin/soc-cases`

## Objective

Onboard a **Windows endpoint** into the home SOC so that telemetry is **usable for detection/triage** and the onboarding can be **proven (audited)** with repeatable validation steps and captured evidence.

## Scope

This onboarding covers Windows endpoints sending telemetry to **Wazuh**, focused on:
- Wazuh agent connectivity and identity (agent visible, consistent hostname)
- Windows event channels required for SOC use (Security + Sysmon as **Must**)
- Wazuh modules relevant for inventory/posture (syscollector + SCA as **Must**)
- Optional quality improvements (System/Application, time sync, basic tags)

**Out of scope (by default):** custom detection rules, tuning, long-term retention, and advanced enrichment.

## Evidence standard (what to save for audit)

For each onboarding, capture at least:
- A screenshot or exported view from Wazuh Dashboard showing the agent **Active** + last keepalive timestamp.
- Command outputs from the endpoint (copy/paste into the ticket/issue or attach as file):
  - `hostname`
  - Security log validation command output
  - Sysmon log validation command output
  - `w32tm /query /status` (time sync)
- If you produce artifacts in this repo, store them under:
  - `artifacts/onboarding/windows/` (create if missing)
  - Naming: `windows_onboarding_<HOST>_YYYY-MM-DD.md`

> **Safety:** never paste secrets (API tokens, passwords, enrollment keys) into artifacts or issues.

---

## Prerequisites

### On the Windows endpoint
- Local admin access (temporarily) to install/verify agent and Sysmon if needed.
- PowerShell available.
- Sysmon installed and logging to **Microsoft-Windows-Sysmon/Operational** (for Must).

### On the Wazuh side
- Wazuh Dashboard accessible from your lab.
- You can locate the agent in Dashboard (no assumption about exact index patterns; use the UI search if needed).

---

## Secrets

If any step requires credentials (Wazuh API, indexer auth, etc.):
- Store them **outside git** under `~/.secrets/`.
- Ensure permissions are restricted (`chmod 600` on Linux).
- Do **not** print secrets to terminal output or artifacts.

This onboarding doc does **not** assume any specific secret file name for Windows onboarding.

---

## Checklist

Legend:
- **Must:** onboarding is **NOT complete** if any Must fails.
- **Should:** recommended; failing Should is acceptable short-term but should be tracked.
- **Could:** optional extras.

Each item includes:
- **How to validate** (commands/UI)
- **Expected result** (PASS criteria)

### MUST

#### M1 — Wazuh agent visible and Active
**How to validate**
1) In Wazuh Dashboard: go to **Agents** (or equivalent section).  
2) Search by endpoint hostname (see M4) and open the agent details page.  
3) Confirm status and last keepalive/last seen.

**Expected result**
- Agent shows **Active/Connected**.
- Last keepalive/last seen is recent (minutes, not hours/days).

#### M2 — Windows Security events are arriving (server-side, auditable)

**How to validate (CLI / Indexer)**
Run on the Linux lab host (repo root), reading indexer auth from `~/.secrets/mini-soc.env` and writing a sanitized artifact:

> **Warning:** do **not** paste Markdown into the terminal. Copy only the commands inside the code block.

```bash
cd ~/soc-cases && set -a && source ~/.secrets/mini-soc.env && set +a && HOST="LAPTOP-RH48MVJ8" && DATE="$(date +%F)" && OUT="artifacts/onboarding/windows/M2_security_${DATE}.md" && mkdir -p artifacts/onboarding/windows && TMP="$(mktemp)" && curl -sk -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" -H 'Content-Type: application/json'  "https://127.0.0.1:9200/wazuh-archives-4.x-*/_search"  -d "{"size":1,"query":{"bool":{"filter":[{"term":{"data.win.system.computer":"${HOST}"}},{"term":{"data.win.system.channel":"Security"}}]}},"sort":[{"@timestamp":{"order":"desc"}}],"_source":["@timestamp","data.win.system.computer","data.win.system.channel"]}"  > "$TMP" && python3 - "$TMP" "$HOST" > "$OUT" <<'PY'
import json,sys
j=json.load(open(sys.argv[1])); host=sys.argv[2]
hits=j.get("hits",{}).get("hits",[])
print(f"# M2 Security channel — {host}")
if not hits:
  print("RESULT: FAIL (no Security events found)")
  sys.exit(0)
src=hits[0].get("_source",{})
print("RESULT: PASS")
print(f"- @timestamp: {src.get('@timestamp')}")
dw=src.get("data",{}).get("win",{}).get("system",{}) if isinstance(src.get("data",{}),dict) else {}
print(f"- data.win.system.computer: {dw.get('computer')}")
print(f"- data.win.system.channel: {dw.get('channel')}")
PY
rm -f "$TMP" && echo "OK: wrote $OUT"
```

**Expected result (PASS)**
- The artifact `artifacts/onboarding/windows/M2_security_YYYY-MM-DD.md` shows `RESULT: PASS` and channel `Security`.
- Timestamp is recent (suggested for onboarding: `< 24h`).

**Auditable evidence (minimum)**
- `artifacts/onboarding/windows/M2_security_YYYY-MM-DD.md` (sanitized; no secrets).

**Note**
- The example uses `HOST="LAPTOP-RH48MVJ8"`. Replace it with your target endpoint hostname.



#### M3 — Sysmon events are arriving (server-side, auditable)

**How to validate (CLI / Indexer)**
Run on the Linux lab host (repo root), reading indexer auth from `~/.secrets/mini-soc.env` and writing a sanitized artifact:

> **Warning:** do **not** paste Markdown into the terminal. Copy only the commands inside the code block.

```bash
cd ~/soc-cases && set -a && source ~/.secrets/mini-soc.env && set +a && HOST="LAPTOP-RH48MVJ8" && DATE="$(date +%F)" && OUT="artifacts/onboarding/windows/M3_sysmon_${DATE}.md" && mkdir -p artifacts/onboarding/windows && TMP="$(mktemp)" && curl -sk -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" -H 'Content-Type: application/json'  "https://127.0.0.1:9200/wazuh-archives-4.x-*/_search"  -d "{"size":1,"query":{"bool":{"filter":[{"term":{"data.win.system.computer":"${HOST}"}},{"term":{"data.win.system.channel":"Microsoft-Windows-Sysmon/Operational"}}]}},"sort":[{"@timestamp":{"order":"desc"}}],"_source":["@timestamp","data.win.system.computer","data.win.system.channel"]}"  > "$TMP" && python3 - "$TMP" "$HOST" > "$OUT" <<'PY'
import json,sys
j=json.load(open(sys.argv[1])); host=sys.argv[2]
hits=j.get("hits",{}).get("hits",[])
print(f"# M3 Sysmon channel — {host}")
if not hits:
  print("RESULT: FAIL (no Sysmon events found)")
  sys.exit(0)
src=hits[0].get("_source",{})
print("RESULT: PASS")
print(f"- @timestamp: {src.get('@timestamp')}")
dw=src.get("data",{}).get("win",{}).get("system",{}) if isinstance(src.get("data",{}),dict) else {}
print(f"- data.win.system.computer: {dw.get('computer')}")
print(f"- data.win.system.channel: {dw.get('channel')}")
PY
rm -f "$TMP" && echo "OK: wrote $OUT"
```

**Expected result (PASS)**
- The artifact `artifacts/onboarding/windows/M3_sysmon_YYYY-MM-DD.md` shows `RESULT: PASS` and channel `Microsoft-Windows-Sysmon/Operational`.
- Timestamp is recent (suggested for onboarding: `< 24h`).

**Auditable evidence (minimum)**
- `artifacts/onboarding/windows/M3_sysmon_YYYY-MM-DD.md` (sanitized; no secrets).

**Note**
- The example uses `HOST="LAPTOP-RH48MVJ8"`. Replace it with your target endpoint hostname.



#### M4 — Hostname consistent (endpoint vs Wazuh agent)
**How to validate**
On endpoint:
```powershell
hostname
```
In Dashboard:
- Confirm the agent identity (name/hostname fields) matches the endpoint hostname you just retrieved.

**Expected result**
- A consistent, stable hostname is used across Windows and Wazuh agent identity.

#### M5 — syscollector present (server-side, auditable)

**How to validate (CLI / Indexer)**
Generate evidence (sanitized) by querying the latest `syscollector` event for the agent:

> **Warning:** do **not** paste Markdown into the terminal. Copy only the commands inside the code block.

```bash
cd ~/soc-cases && set -a && source ~/.secrets/mini-soc.env && set +a && AGENT_NAME="LAPTOP-RH48MVJ8" && DATE="$(date +%F)" && OUT="artifacts/onboarding/windows/M5_syscollector_${DATE}.md" && mkdir -p artifacts/onboarding/windows && TMP="$(mktemp)" && curl -sk -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" -H 'Content-Type: application/json'   "https://127.0.0.1:9200/wazuh-archives-4.x-*/_search"   -d "{"size":1,"query":{"bool":{"filter":[{"term":{"agent.name":"${AGENT_NAME}"}},{"term":{"decoder.name":"syscollector"}}]}},"sort":[{"@timestamp":{"order":"desc"}}],"_source":["@timestamp","agent.id","agent.name","decoder.name","location"]}"   > "$TMP" && python3 - "$TMP" "$AGENT_NAME" > "$OUT" <<'PY'
import json,sys
j=json.load(open(sys.argv[1]))
agent=sys.argv[2]
hits=j.get("hits",{}).get("hits",[])
print(f"# M5 Syscollector — {agent}")
if not hits:
  print("RESULT: FAIL (no syscollector events found for agent)")
  sys.exit(0)
src=hits[0].get("_source",{})
print("RESULT: PASS")
print(f"- @timestamp: {src.get('@timestamp')}")
print(f"- agent.id: {src.get('agent',{}).get('id')}")
print(f"- agent.name: {src.get('agent',{}).get('name')}")
print(f"- decoder.name: {src.get('decoder',{}).get('name')}")
print(f"- location: {src.get('location')}")
PY
rm -f "$TMP" && echo "OK: wrote $OUT"
```

**Expected result (PASS)**
- The artifact `artifacts/onboarding/windows/M5_syscollector_YYYY-MM-DD.md` shows `RESULT: PASS`.
- `@timestamp` is recent (suggested for onboarding: `< 24h`).

**Auditable evidence (minimum)**
- `artifacts/onboarding/windows/M5_syscollector_YYYY-MM-DD.md` (sanitized; no secrets).

**Note**
- The example uses `AGENT_NAME="LAPTOP-RH48MVJ8"`. Replace it with your target agent name.



#### M6 — SCA present (server-side, auditable)

**How to validate (CLI / Indexer)**
Generate evidence (sanitized) by querying the latest `sca` event for the agent:

> **Warning:** do **not** paste Markdown into the terminal. Copy only the commands inside the code block.

```bash
cd ~/soc-cases && set -a && source ~/.secrets/mini-soc.env && set +a && AGENT_NAME="LAPTOP-RH48MVJ8" && DATE="$(date +%F)" && OUT="artifacts/onboarding/windows/M6_sca_${DATE}.md" && mkdir -p artifacts/onboarding/windows && TMP="$(mktemp)" && curl -sk -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}" -H 'Content-Type: application/json'   "https://127.0.0.1:9200/wazuh-archives-4.x-*/_search"   -d "{"size":1,"query":{"bool":{"filter":[{"term":{"agent.name":"${AGENT_NAME}"}},{"term":{"decoder.name":"sca"}}]}},"sort":[{"@timestamp":{"order":"desc"}}],"_source":["@timestamp","agent.id","agent.name","decoder.name","location"]}"   > "$TMP" && python3 - "$TMP" "$AGENT_NAME" > "$OUT" <<'PY'
import json,sys
j=json.load(open(sys.argv[1]))
agent=sys.argv[2]
hits=j.get("hits",{}).get("hits",[])
print(f"# M6 SCA — {agent}")
if not hits:
  print("RESULT: FAIL (no SCA events found for agent)")
  sys.exit(0)
src=hits[0].get("_source",{})
print("RESULT: PASS")
print(f"- @timestamp: {src.get('@timestamp')}")
print(f"- agent.id: {src.get('agent',{}).get('id')}")
print(f"- agent.name: {src.get('agent',{}).get('name')}")
print(f"- decoder.name: {src.get('decoder',{}).get('name')}")
print(f"- location: {src.get('location')}")
PY
rm -f "$TMP" && echo "OK: wrote $OUT"
```

**Expected result (PASS)**
- The artifact `artifacts/onboarding/windows/M6_sca_YYYY-MM-DD.md` shows `RESULT: PASS`.
- `@timestamp` is recent (suggested for onboarding: `< 24h`).

**Auditable evidence (minimum)**
- `artifacts/onboarding/windows/M6_sca_YYYY-MM-DD.md` (sanitized; no secrets).

**Note**
- SCA events may also appear for the manager (agent `000`). For Windows onboarding, validate by the endpoint agent name (`agent.name`).
- The example uses `AGENT_NAME="LAPTOP-RH48MVJ8"`. Replace it with your target agent name.



### SHOULD

#### S1 — System events are arriving
**How to validate (endpoint)**
```powershell
wevtutil qe System /c:5 /rd:true /f:text
```
**Expected result**
- Recent System events exist locally and are visible for the agent in Dashboard/event search.

#### S2 — Application events are arriving
**How to validate (endpoint)**
```powershell
wevtutil qe Application /c:5 /rd:true /f:text
```
**Expected result**
- Recent Application events exist locally and are visible for the agent in Dashboard/event search.

#### S3 — Time sync / clock health
**How to validate (endpoint)**
```powershell
w32tm /query /status
```
**Expected result**
- Clock is synchronized; time source/stratum look reasonable; no large drift indicators.

#### S4 — Tags / grouping (Wazuh Agent Groups) — Official mechanism

**Official mechanism**
- We use **Wazuh Agent Groups** as the official “tags / grouping” mechanism for Windows onboarding.

**Minimum groups (MVP)**
- `windows` → the agent is Windows
- `lab` → environment/lab (home SOC)
- `onboarded` → state “onboarding complete” (gates PASS)

> The `default` group may coexist. PASS is based on the presence of the minimum groups and the agent’s membership.

**How to validate (CLI — groups exist)**
Run on the Linux lab host where Docker runs Wazuh:
```bash
MANAGER_CTN="$(docker ps --format '{{.Names}}' | grep -E 'wazuh\.manager|wazuh-manager|wazuh_manager' | head -n 1)"
docker exec -i "$MANAGER_CTN" /var/ossec/bin/agent_groups -l
```
**Expected result**
- Output includes the groups: `windows`, `lab`, `onboarded` (and typically `default`).
- Group counters look coherent (e.g., `windows (1)` if one Windows agent is assigned).

**How to validate (CLI — assign agent to a group)**
Assign by agent ID (example uses ID `001`):
```bash
MANAGER_CTN="$(docker ps --format '{{.Names}}' | grep -E 'wazuh\.manager|wazuh-manager|wazuh_manager' | head -n 1)"
docker exec -i "$MANAGER_CTN" /var/ossec/bin/agent_groups -a -i 001 -g windows
```
Validate membership:
```bash
MANAGER_CTN="$(docker ps --format '{{.Names}}' | grep -E 'wazuh\.manager|wazuh-manager|wazuh_manager' | head -n 1)"
docker exec -i "$MANAGER_CTN" /var/ossec/bin/agent_groups -s -i 001
```
**Expected result**
- The membership output includes `windows` (and, when applicable, `lab` and `onboarded`), e.g.:
  - `...belongs to groups: default, windows.`

**How to validate (UI — exact path)**
In Wazuh Dashboard:
1) **Agents** → search the agent by name/ID  
2) Open the agent detail page  
3) Locate **Groups** and confirm it contains `windows` (and, when applicable, `lab`, `onboarded`).

**PASS / FAIL (MVP)**
- **PASS** if:
  - Groups `windows`, `lab`, `onboarded` exist, and
  - Target Windows agent belongs to `windows`, and
  - For the lab environment, the agent belongs to `lab`, and
  - When onboarding is finalized, the agent belongs to `onboarded`.
- **FAIL** if any required group does not exist, or the agent is missing membership in `windows` / `lab` / `onboarded` when applicable.

---

### COULD (examples)

Adopt only what you want and document validation + PASS criteria:
- C1 — Key EventID coverage checks (Security + Sysmon)
- C2 — Sysmon config version/hash validation
- C3 — Extra telemetry (PowerShell logging, Defender events)
- C4 — Baseline volume / “last event” metrics (24h)

---

## Troubleshooting (common failures)

### T1 — Agent not visible / disconnected
**Symptoms**
- Agent does not appear in Dashboard, or shows Disconnected/Inactive.

**Checks**
- On endpoint: confirm Wazuh agent service is running (service name depends on installer).
- Confirm endpoint can reach manager (network/DNS/firewall).
- Check agent logs on endpoint (path depends on agent installation).

**Fix**
- Restart agent service.
- Re-check enrollment/registration.
- If persistent, capture endpoint agent logs and relevant manager-side logs and escalate.

### T2 — Security log present locally but not ingested
**Symptoms**
- Local Security events exist, but Dashboard shows none.

**Checks**
- Confirm agent configuration collects Security channel.
- Confirm filtering is not dropping these events.

**Fix**
- Update agent log collection config to include Security.
- Generate a test event and re-check ingestion.

### T3 — Sysmon channel empty / Sysmon not installed
**Symptoms**
- Sysmon Operational log is empty; Sysmon service not present.

**Fix**
- Install Sysmon and deploy a Sysmon config.
- Revalidate local Sysmon events first, then ingestion into Wazuh.

### T4 — Hostname mismatch
**Symptoms**
- Endpoint hostname differs from agent identity or changes unexpectedly.

**Fix**
- Standardize naming; document mapping if using asset IDs.
- Ensure searches use the stable identifier.

### T5 — Time drift breaks correlation
**Symptoms**
- Timestamps off; correlation windows fail.

**Fix**
- Fix time source (NTP/domain time) and re-check `w32tm /query /status`.

---

## Handoff to SOC Engineer (optional automation)

If you want a single script that generates an auditable artifact + PASS/FAIL, request:

**Prompt (copy/paste):**
> Actuá como SOC Engineer del home SOC. Implementar un check automatizado de onboarding Windows ejecutable y auditable.
> - Crear `tools/windows_onboarding_check.sh` (Linux-side) que genere `artifacts/onboarding/windows/windows_onboarding_<agent>_YYYY-MM-DD.md`.
> - Debe aceptar `--agent "<name>"` y `--date YYYY-MM-DD` (opcional; default hoy).
> - Validar mínimo: agent activo/visible; Security events llegan; Sysmon events llegan; syscollector presente; SCA presente; hostname consistente (si hay campo disponible).
> - No volcar secretos. Si requiere auth (Wazuh API / indexer), leer desde `~/.secrets/` y sanitizar outputs.
> - Exit code 0 si PASS y !=0 si FAIL.
> - Entregables: PR con script + update de `docs/onboarding_windows.md` con cómo correrlo + ejemplo de output sanitizado.
---

## Quick run (recommended)

> ⚠️ Important: copy/paste only the command below into the terminal. Do not paste markdown blocks.

## Run
```bash
set -a && source ~/.secrets/mini-soc.env && set +a && \
tools/onboarding/windows/windows_onboarding_audit.sh --host "<HOSTNAME>" --agent "<AGENT_NAME>"
```

## What it generates (artifacts)
A single run produces these sanitized artifacts (no secrets):
- `artifacts/onboarding/windows/M2_security_YYYY-MM-DD.md`
- `artifacts/onboarding/windows/M3_sysmon_YYYY-MM-DD.md`
- `artifacts/onboarding/windows/M5_syscollector_YYYY-MM-DD.md`
- `artifacts/onboarding/windows/M6_sca_YYYY-MM-DD.md`

## PASS/FAIL criteria
- **PASS**: wrapper exit code `0` AND all 4 artifacts contain `RESULT: PASS`.
- **FAIL**: wrapper exit code `!= 0` OR any artifact contains `RESULT: FAIL`.

## Notes
- `--host` targets M2/M3 using `data.win.system.computer`.
- `--agent` targets M5/M6 using `agent.name`.
- Optional: `--date YYYY-MM-DD` (default: today).
