# Changelog — asterion-firewall-analysis

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
Este proyecto todavía no tiene releases etiquetados en git.

## [Unreleased]

### Added
- Análisis real del firewall de la máquina (Application Firewall + `pf`
  en macOS, código para ufw/nftables/iptables en Linux sin probar en real
  todavía) — hallazgos con severidad y recomendación, puntaje 0-100.
- Historial de análisis persistido (`/api/v1/history`).
- **Reglas de firewall declarables y probadas de verdad en un Asterion
  Lab efímero** (`/api/v1/rule-sets`, `POST .../lab-test`): mismo
  vocabulario que `asterion-lab/spec.FirewallRule`, mismo patrón de dos
  VMs (server con `ufw` real + client que prueba con `nc`) documentado en
  `asterion-core/README.md`. Cada regla se prueba contra un listener real
  arrancado a propósito en el server, para que un `allow`/`deny` pruebe
  de verdad que `ufw` dejó pasar o bloqueó tráfico — no que "no había
  nada ahí". El laboratorio se destruye siempre al terminar.
- Frontend propio (React + Vite + pnpm): sparkline de puntaje en el
  tiempo y barras de severidad (SVG a mano, sin dependencia de gráficos),
  sección de reglas de firewall con el flujo de "Probar en un Lab".
  Embebido de verdad en el dashboard local de Asterion vía el reverse
  proxy de plugins de `asterion-core`.
- `plugin.yaml` generado desde `plugin.ast` (Asterion Language,
  `Contract.*`) — fuente editable versionada junto al código.
