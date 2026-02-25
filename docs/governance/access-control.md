# Access Control (MVP) — Wazuh / OpenSearch Dashboards

## Objetivo
Implementar un modelo mínimo (MVP) de control de acceso para operar el Dashboard de Wazuh con cuentas/roles mínimos y evidencia auditable (para P1 “Plataforma → Control de acceso → Cuentas/roles mínimas”).

## Roles (MVP)

### Admin / Engineer (Plataforma)
**Uso previsto**
- Solo tareas de plataforma: configuración, upgrades, RBAC, mantenimiento, troubleshooting.

**Regla operativa**
- No usar el admin para triage/consultas diarias salvo emergencia.

> Nota: el usuario Linux del servidor (ej. `socadmin`) NO es necesariamente el “admin” de Wazuh/OpenSearch; son identidades distintas.

### Analyst (Triage / Consultas)
**Uso previsto**
- Acceso diario al dashboard: ver alertas/eventos, búsquedas y paneles.
- Sin permisos de escritura/administración.

**Permisos esperados (alto nivel)**
- ✅ Lectura de saved objects necesarios (ej. index-patterns) para que el plugin de Wazuh cargue correctamente.
- ✅ Lectura en índices de Wazuh (ej. `wazuh-alerts-*`) para búsquedas/visualización.
- ❌ Escritura en índices de Wazuh.
- ❌ Acceso a Security API (roles/rolesmapping/internal users).

---

## Gestión de secretos (obligatorio)
- Los secretos **no** van a Git.
- Se almacenan solo en: `~/.secrets/mini-soc.env` con permisos `600`.
- El repo puede contener solo “mapeos” (ej. `pass_env`), nunca passwords.

Convención:
- Por cada usuario, se crea/usa una variable `*_PASS` en `~/.secrets/mini-soc.env` (p. ej. `LUCIANO_VENTRICE_PASS`).

---

## Scripts

### 1) Crear usuario Analyst (repetible y auditable)
**Script**
- `tools/access-control/create-analyst-user.sh <username>`

**Qué hace**
- Genera o reutiliza la password del usuario en `~/.secrets/mini-soc.env` (no imprime secretos).
- Crea/actualiza el usuario de OpenSearch Security de forma **persistente** (edita `internal_users.yml` dentro del contenedor + `securityadmin.sh`).
- **Clona backend_roles desde el usuario plantilla `analyst`** para asegurar el mismo comportamiento en UI (evita el error de Wazuh plugin por permisos incompletos).
- Hace flush del cache de seguridad.
- Asegura que el usuario figure en `tools/access-control/users.yml` en `credential_map` (solo `pass_env`, sin password).

**Evidencia**
- Logs auditables en `artifacts/platform/access-control/`:
  - `rbac-create-analyst-YYYY-MM-DD_HHMMSS.log`
  - `raw-create-YYYY-MM-DD_HHMMSS/` (payload redactado, outputs auxiliares)

**Salida**
- Termina con `=== RESULT: PASS ===` o `=== RESULT: FAIL ===`
- Imprime `EVIDENCE_LOG` y `RAW_DIR`.

### 2) Auditoría RBAC de usuarios (repetible y auditable)
**Script**
- `tools/access-control/verify-users.sh`

**Qué valida**
A) **Auditoría global (sin passwords, usando admin cert dentro del contenedor)**
- `internalusers`, `rolesmapping`, `roles`
- Tabla resumen: `username / backend_roles / effective_roles / class / risk_flags`

B) **Functional tests (solo para usuarios listados en `tools/access-control/users.yml`)**
- ✅ `saved_objects/_find` debe ser `HTTP=200`
- ✅ búsqueda en `wazuh-alerts-*` debe ser `HTTP=200`
- ❌ escritura en `wazuh-alerts-*` debe ser `HTTP=403`
- ❌ Security API roles/rolesmapping debe ser `HTTP=403`
- ❌ crear saved object debe ser `HTTP=401` o `HTTP=403`

**Evidencia**
- Logs auditables en `artifacts/platform/access-control/`:
  - `rbac-users-verify-YYYY-MM-DD_HHMMSS.log`
  - `raw-YYYY-MM-DD_HHMMSS/`

**Salida**
- Termina con `=== RESULT: PASS ===` o `=== RESULT: FAIL ===`
- Imprime `EVIDENCE_LOG` y `RAW_DIR`.

---

## Runbook — Crear un analyst y validar end-to-end

### Paso 1 — Crear/actualizar el usuario (backend)
Ejecutar:
- `tools/access-control/create-analyst-user.sh <username>`

Esperado:
- `=== RESULT: PASS ===`
- Se imprime `EVIDENCE_LOG` + `RAW_DIR`

### Paso 2 — Validación UI (Wazuh Dashboard)
1) Ingresar al Dashboard con el nuevo usuario.
2) Confirmar que el plugin de Wazuh carga sin errores (ej. no aparece “Pattern Handler / getPatternList”).
3) Confirmar navegación/visualización: alertas/eventos/búsquedas.

### Paso 3 — Auditoría RBAC (backend + functional)
Ejecutar:
- `tools/access-control/verify-users.sh`

Esperado:
- `=== RESULT: PASS ===`
- Los usuarios tipo analyst deben:
  - poder leer (200) y
  - fallar en acciones admin / write (403/401 según corresponda)

---

## Ubicación de evidencias para Git
- Todo lo auditable queda dentro del repo en:
  - `soc-cases/artifacts/platform/access-control/`

Nota:
- No incluir `~/.secrets/mini-soc.env` en Git bajo ningún concepto.

