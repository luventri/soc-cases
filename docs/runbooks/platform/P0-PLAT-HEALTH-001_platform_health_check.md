# Runbook - P0 Platform Health Check: Wazuh single-node Docker estable

**Check ID:** P0-PLAT-HEALTH-001  
**Artefacto:** `artifacts/platform/health/platform_health_YYYY-MM-DD.md`  
**Script:** `tools/platform_health.sh`  
**Repo root:** `/home/socadmin/soc-cases`  
**Última actualización:** 2026-02-24

---

## Objetivo

Validar rápidamente que el stack **Wazuh single-node en Docker** está estable (servicios levantados y saludables) y generar evidencia **auditable** en un artefacto versionado en Git.

## Alcance

Incluye:
- Estado de contenedores del stack (Docker Compose).
- Acceso al **Wazuh Indexer** y verificación de health **autenticado** (sin volcar secretos).
- Generación de artefacto Markdown con resultados.

No incluye:
- Tuning de performance o capacity planning.
- Investigaciones de detección/alertas (eso es “case workflow”).

## Prerequisitos

En la máquina del SOC (usuario `socadmin`):

- Repo del SOC clonado en `/home/socadmin/soc-cases` y con permisos de ejecución sobre `tools/platform_health.sh`.
- Docker y Docker Compose operativos.
- Stack Wazuh single-node desplegado con compose en:
  - `/home/socadmin/wazuh-docker/single-node/docker-compose.yml`
- Acceso al dashboard de Wazuh (según tu entorno):
  - Dashboard local típico: `https://localhost:5601`
  - Alternativa: `https://<HOST_O_IP>:5601`

## Secretos (sin fugas)

El script soporta health autenticado del indexer leyendo variables desde:

- `~/.secrets/mini-soc.env`

Buenas prácticas mínimas:
- Permisos: `chmod 600 ~/.secrets/mini-soc.env`
- **Nunca** commitear archivos de secretos.
- Evitar “echo” de variables sensibles en terminal / logs.
- El artefacto generado debe estar **sanitizado** (sin user/pass/tokens).

> Nota: Si el script no encuentra `~/.secrets/mini-soc.env`, debe correr igualmente pero puede degradar el chequeo autenticado (según implementación).

---

## Pasos (local)

> ⚠️ Advertencia: **no pegues Markdown en la terminal**. Copiá únicamente los comandos dentro de bloques de código.

1) Ir al root del repo del SOC (donde exista `tools/`):

```bash
cd /home/socadmin/soc-cases

Verificar que el script existe y es ejecutable:

ls -l tools/platform_health.sh
chmod +x tools/platform_health.sh

(Opcional) Verificar que el archivo de secretos existe y permisos:

ls -l ~/.secrets/mini-soc.env
chmod 600 ~/.secrets/mini-soc.env

Ejecutar el check:

bash tools/platform_health.sh

Confirmar que se generó el artefacto (por fecha):

ls -l artifacts/platform/health/platform_health_YYYY-MM-DD.md
Pasos (con Git)

Revisar cambios:

git status

Agregar el artefacto nuevo/modificado:

git add artifacts/platform/health/platform_health_YYYY-MM-DD.md

Commit (mensaje sugerido):

git commit -m "chore: platform health check YYYY-MM-DD"

Push:

git push origin main
PASS / FAIL
PASS (criterios mínimos)

Docker Compose muestra contenedores del stack en running (sin reinicios constantes).

El chequeo de indexer health responde OK (HTTP 200 o estado equivalente) cuando está configurado el auth.

El artefacto platform_health_YYYY-MM-DD.md se generó y contiene:

Fecha/hora de ejecución

Resumen de checks

Evidencia mínima (estado contenedores + health indexer)

Sin secretos

FAIL (ejemplos)

Contenedores caídos o en restart loop.

Indexer no responde / responde con error (401/403 si auth mal, 5xx si servicio mal).

No se genera artefacto o queda vacío/incompleto.

Se detectan secretos en texto plano (esto es un FAIL automático).

Ejemplo de output esperado (sanitizado)

Ejemplo ilustrativo. No copiar/pegar como comandos.

Platform Health - Wazuh single-node
Date: YYYY-MM-DD

[Docker Compose]
- wazuh-manager: running
- wazuh-indexer: running
- wazuh-dashboard: running

[Indexer Health - Authenticated]
- Endpoint: https://127.0.0.1:9200/_cluster/health
- Status: green
- HTTP: 200

Result: PASS
Artifact: artifacts/platform/health/platform_health_YYYY-MM-DD.md
Troubleshooting (mínimo)

permission denied al ejecutar el script

Solución: chmod +x tools/platform_health.sh o ejecutar con bash tools/platform_health.sh.

No aparece el artefacto

Verificar cwd (estar en el repo), permisos de escritura y path artifacts/platform/health/.

Ejecutar: mkdir -p artifacts/platform/health.

401/403 contra el indexer

Revisar credenciales en ~/.secrets/mini-soc.env y permisos 600.

Confirmar endpoint/puerto correcto del indexer.

Timeout / conexión rechazada al indexer

Verificar que el contenedor del indexer está running.

Revisar puertos publicados y firewall local.

Notas de seguridad (bind 0.0.0.0)

Evitar exponer servicios del stack en 0.0.0.0 salvo que sea estrictamente necesario.

Si se publica 0.0.0.0:5601 (dashboard) o 0.0.0.0:9200 (indexer), aplicar como mínimo:

Restricción por firewall/ACL a IPs de administración.

Autenticación fuerte (y rotación de credenciales).

Preferir acceso vía VPN/SSH tunnel.

No incluir URLs internas sensibles ni credenciales en artefactos o issues.
