# Runbook — P1 Retención y Backups: Retención + backup plan

**Check ID:** P1-PLAT-BACKUP-001  
**Scripts:**  
- `tools/backup_run.sh`  
- `tools/backup_restore_test.sh`  

**Evidencia:** `artifacts/platform/backup/backup_test_YYYY-MM-DD.md`  
**Backup destino:** `socbackup@192.168.242.129:/srv/soc-backups/latest`  
**Última actualización:** 2026-02-24

---

## Objetivo

Definir y ejecutar un plan simple, seguro y repetible de **retención** y **backups** para la plataforma Wazuh (single-node en Docker), con evidencia auditable de “restore verificado”.

---

## Prerrequisitos (hosts)

En `soc-core`:
- docker + docker compose
- rsync
- acceso SSH por clave a `soc-backup` (clave: `~/.ssh/soc_backup_ed25519`)

En `soc-backup`:
- openssh-server
- rsync
- directorio destino: `/srv/soc-backups` (owner `socbackup`, permisos 700)


## Alcance (qué se respalda)

### 1) Plataforma Wazuh (Docker)

**Configuración del host (bind-mounted):**
- Compose: `/home/socadmin/wazuh-docker/single-node/docker-compose.yml`
- Config/certs: `/home/socadmin/wazuh-docker/single-node/config/`

**Volúmenes Docker (exportados a tar.gz):**
- Manager:
  - `single-node_wazuh_api_configuration`
  - `single-node_wazuh_etc`
  - `single-node_wazuh_logs`
  - `single-node_wazuh_queue`
  - `single-node_wazuh_var_multigroups`
  - `single-node_wazuh_integrations`
  - `single-node_wazuh_active_response`
  - `single-node_wazuh_agentless`
  - `single-node_wazuh_wodles`
  - `single-node_filebeat_etc`
  - `single-node_filebeat_var`
- Dashboard:
  - `single-node_wazuh-dashboard-config`
  - `single-node_wazuh-dashboard-custom`
- Indexer:
  - `single-node_wazuh-indexer-data`

> Fuente de verdad de volúmenes/binds: `docker compose config` (sanitizado) en `tmp/wazuh_single_node_resolved.yml`.

### 2) Repo del SOC (código + documentación)
- `/home/socadmin/soc-cases/`
- Incluye: `tools/`, `docs/`, `playbooks/`, `.github/`
- Excluye: `tmp/` y `artifacts/` (evita backups recursivos y ruido)

---

## Retención (home-lab)

- **Backups remotos:** 1 copia “latest” (sin histórico)
  - Justificación: simplicidad y menor consumo de disco.
  - Mitigación: swap atómico (`latest.next` → `latest` solo si termina OK).
- **Artefactos del repo (`artifacts/`):** mantener ~30 días (manual/housekeeping).
- **Logs/colas:** quedan cubiertos por el backup “latest” (volúmenes).

> Si el SOC crece, migrar a retención N (p.ej. 7/30) con rotación.

---

## Frecuencia y ubicación

- **Frecuencia recomendada:** semanal (diaria si hay cambios frecuentes).
- **Ubicación primaria:** `socbackup@192.168.242.129:/srv/soc-backups/latest`
- **Staging local temporal:** `~/soc-cases/tmp/backup_stage_*` (se elimina al terminar)

---

## Consideraciones de secretos

- No respaldar ni commitear `~/.secrets/`.
- Proteger `~/.secrets/mini-soc.env` con permisos `600`.
- Proteger la SSH key del backup:
  - `~/.ssh/soc_backup_ed25519` (permisos `600`)

---

## Procedimiento de backup (repetible)

En `soc-core`:

```bash
cd /home/socadmin/soc-cases
./tools/backup_run.sh
```

Qué hace:

- Copia repo (sin tmp/ ni artifacts/)
- Copia compose + config dir
- Exporta volúmenes a docker-volumes/*.tar.gz
- Publica remoto en latest con swap atómico

## Procedimiento de restore (prueba) y validación
Restore test (sin tocar producción)
```bash
cd /home/socadmin/soc-cases
./tools/backup_restore_test.sh
```

## Criterio de éxito (restore verificado):

- MANIFEST.txt presente

- directorios repo/, wazuh/, docker-volumes/ presentes

- todos los *.tar.gz pasan tar -tzf sin error

- wazuh/docker-compose.yml y wazuh/config/ presentes

## Evidencia: generar artifacts/platform/backup/backup_test_YYYY-MM-DD.md.

- Restore completo (manual, si hiciera falta)

- Traer backup latest/ desde soc-backup a un directorio local (p.ej. /tmp/restore_full)

- Detener stack:

- docker compose -f /home/socadmin/wazuh-docker/single-node/docker-compose.yml down

- Restaurar config del host (compose + config dir) desde backup.

- Restaurar volúmenes:

- crear si faltan: docker volume create <name>

- importar tar.gz al volumen:
```bash
docker run --rm -v <VOL>:/v -v /tmp/restore_full/docker-volumes:/in ubuntu:24.04 \
  bash -lc "rm -rf /v/* && tar -xzf /in/<VOL>.tar.gz -C /v"
```
- Levantar stack:
```bash
docker compose -f /home/socadmin/wazuh-docker/single-node/docker-compose.yml up -d
```

## Validar:

- docker compose ps

- Dashboard responde (HTTP 302 a login)

- Indexer health cluster (HTTP 200, status green/yellow)

### C) Disaster Recovery (agregar)

## Recuperación si se pierde soc-core (Disaster Recovery)

Si `soc-core` se pierde, los scripts no estarán disponibles localmente. Procedimiento recomendado:

1) Crear una VM nueva (soc-core2) con Ubuntu Server LTS.
2) Instalar dependencias mínimas: docker + compose, rsync, git.
3) Clonar el repositorio del SOC:
   - `git clone https://github.com/luventri/soc.git`
4) Configurar acceso SSH por clave hacia `soc-backup` y verificar conectividad.
5) Ejecutar:
   - `./tools/backup_restore_apply.sh --i-understand-this-will-restore`
6) Levantar Wazuh y validar con `./tools/platform_health.sh`.

## Restore APPLY (restauración real en DR)

Este restore aplica cambios (config + volúmenes) y está pensado para un host nuevo (p.ej. `soc-core2`) o DR.

Script:
- `tools/backup_restore_apply.sh`

Ejecutar:
```bash
cd /home/socadmin/soc-cases
./tools/backup_restore_apply.sh --i-understand-this-will-restore
```

Luego levantar el stack:
```bash
docker compose -f /home/socadmin/wazuh-docker/single-node/docker-compose.yml up -d
./tools/platform_health.sh
```
