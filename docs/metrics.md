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
