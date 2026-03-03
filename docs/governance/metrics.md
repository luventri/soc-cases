# MET-001 Weekly SLO Pack

## Objetivo
Formalizar un reporte semanal auditable de salud del SOC usando fuentes ya existentes (coverage, ops-alerts y CI), con umbrales y acciones explícitas.

## Alcance (MET-001)
KPIs obligatorios de salud operativa:
- Cobertura de telemetría (evidencia diaria disponible en la semana)
- Confiabilidad de `ops-alerts` (frecuencia y fallas)
- Salud de controles CI requeridos (`gitleaks`, `policy`, `lint-audit`)

Métricas de incidente (opcionales por ahora):
- MTTD
- MTTR

## Entradas de datos
- `artifacts/telemetry/coverage/coverage_24h_YYYY-MM-DD.md`
- `artifacts/platform/ops-alerts/ops_alerts_YYYY-MM-DD.md`
- GitHub Actions (últimos runs en `main`)

## Generación del reporte semanal
Script:
- `tools/metrics/weekly_metrics.sh`

Uso:
- Semana actual (UTC):
  - `tools/metrics/weekly_metrics.sh`
- Semana de referencia (fecha UTC):
  - `tools/metrics/weekly_metrics.sh 2026-03-03`

Salida:
- `artifacts/metrics/weekly_metrics_YYYY-WW.md`

## Umbrales base y acciones
1. Coverage evidence days
- Umbral: `>= 5` reportes diarios por semana y último reporte con eventos `> 0`
- Si falla: regenerar reportes faltantes y revisar ingest/scheduler

2. Ops alerts reliability
- Umbral: `>= 5` corridas por semana y `<= 1` fallo semanal
- Si falla: abrir/seguir issues de remediación y estabilizar checks/timer

3. Required CI controls
- Umbral: controles requeridos saludables en ventana de 7 días (`gitleaks`, `policy`, `lint-audit`)
- Si falla: corregir checks antes de merges de riesgo alto

## Criterio de estado semanal
- `PASS`: ningún KPI en FAIL
- `WARN`: sin FAIL, pero al menos un KPI en WARN
- `FAIL`: al menos un KPI en FAIL

## Evidencia mínima esperada
Cada `weekly_metrics_YYYY-WW.md` debe incluir:
- Ventana temporal
- Tabla KPI con umbral, estado y acción
- Detalle de fuentes usadas
- Resultado semanal final (PASS/WARN/FAIL)

## Operación recomendada
- Ejecutar 1 vez por semana durante la revisión GOV-003.
- Si el resultado es `WARN` o `FAIL`, registrar acciones en el artifact semanal de governance.

---

# MET-002 Trend Tracking (Baselines + Drift)

## Objetivo
Establecer baseline de canales críticos de Windows y detectar desvíos relevantes de volumen para disparar investigación temprana.

## Alcance (MET-002)
- Canales iniciales: `Security`, `Microsoft-Windows-Sysmon/Operational`, `System`, `Application`.
- Fuente: artifacts diarios de coverage (`coverage_24h_YYYY-MM-DD.md`).
- Salida: baseline + drift con estado (`PASS/WARN/FAIL`) y acción por canal.

## Runner
Script:
- `tools/metrics/windows_channel_baseline_drift.sh`

Uso:
- Corrida por defecto (fecha UTC actual):
  - `tools/metrics/windows_channel_baseline_drift.sh`
- Corrida para fecha específica:
  - `tools/metrics/windows_channel_baseline_drift.sh 2026-03-03`

Configuración opcional por env:
- `MET_BASELINE_LOOKBACK_DAYS` (default `14`)
- `MET_DRIFT_THRESHOLD_PCT` (default `40`)
- `MET_MIN_BASELINE_SAMPLES` (default `3`)
- `MET_CHANNELS_CSV` (default canales críticos de Windows)
- `MET_CREATE_ISSUE_ON_FAIL` (`1` para intentar crear GitHub Issue en FAIL)

## Evidencia generada
- `artifacts/telemetry/baselines/windows_channel_baseline_YYYY-MM-DD.json`
- `artifacts/telemetry/baselines/windows_channel_baseline_drift_YYYY-MM-DD.md`

## Criterio de evaluación
- `PASS`: baseline suficiente y sin desvíos sobre umbral.
- `WARN`: baseline todavía inmaduro (muestras insuficientes).
- `FAIL`: desvío mayor al umbral en canales con volumen significativo.

## Operación recomendada
- Ejecutar junto con `MET-001` en la revisión semanal GOV-003.
- Ante `FAIL`, abrir/actualizar issue de remediación y validar en la siguiente corrida.
