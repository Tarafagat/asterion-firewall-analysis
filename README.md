# asterion-firewall-analysis

Plugin de Asterion que analiza el firewall real de la máquina donde corre
y devuelve **hallazgos con severidad y recomendación**, con un puntaje
0-100 — no solo "está prendido o apagado".

## Por qué esto es un plugin y no algo del core

Asterion Core ya detecta el firewall (`internal/runtime` + `asterion local
doctor`): qué backend hay presente, y si se puede leer su estado sin
privilegios. Eso es correcto que viva en el core — es la base que el
propio Runtime necesita para saber si es seguro exponerse.

Pero *interpretar* ese dato crudo (¿esta regla es peligrosa?, ¿qué puntaje
tiene la configuración?, ¿qué se recomienda?) es opinático y va a cambiar
con el tiempo — nuevos puertos sensibles, nuevos criterios, nuevas
heurísticas. Meter eso en el core obligaría a esperar un release de
Asterion cada vez que cambia un criterio de seguridad. Como plugin,
evoluciona solo, se instala solo quien lo quiere, y puede iterar rápido.

**División de responsabilidad:** el core detecta y expone el dato crudo.
Este plugin lo interpreta.

## Por qué no importa `asterion-core/internal/runtime`

Dos motivos, uno técnico y uno de diseño:

1. `internal/` es un paquete interno de Go — otro módulo (este repo) ni
   podría importarlo aunque quisiera.
2. Un plugin es, por diseño de Asterion, un proceso independiente en su
   propio repo — no un plan de asterion-core. Repite las mismas técnicas
   de detección (mismos comandos: `pfctl`, `socketfilterfw`, `ufw`, `nft`,
   `iptables`) en vez de depender del binario de Core en tiempo de
   ejecución, exactamente como ya hace `dummy-fs-provider` (el plugin de
   referencia del Asterion Plugin Contract) con sus propias operaciones.

## Estado real (honesto)

- **macOS: real y probado en esta máquina** — Application Firewall y pf.
- **Linux (ufw/nftables/iptables): código escrito, sin probar en una
  máquina Linux real todavía** — mismo criterio honesto que el resto del
  ecosistema Asterion (ver READMEs de asterion-core/asterion-lab).
- El análisis de reglas específicas (`analyzeUFW`/`analyzeRuleText`) es
  una heurística sobre texto, no un parser completo de sintaxis
  ufw/nft/iptables — cubre el caso común (puerto sensible + ALLOW +
  0.0.0.0/0 o "Anywhere"), y siempre deja el `raw_summary` disponible
  para revisión manual de lo que la heurística no capture.

## API

| Método | Path | Qué hace |
|---|---|---|
| GET | `/health` | Health check (siempre healthy — no depende de estado externo) |
| GET | `/api/v1/analysis` | Corre un análisis fresco, no lo persiste (resource, solo lectura) |
| POST | `/api/v1/analysis` | Corre un análisis y lo guarda en el historial (action) |
| GET | `/api/v1/history?limit=N` | Últimos N análisis guardados (default 20) |
| GET/POST | `/api/v1/rule-sets` | Listar / crear conjuntos de reglas de firewall propios |
| GET/PUT/DELETE | `/api/v1/rule-sets/{id}` | Leer / editar / borrar un conjunto de reglas |
| POST | `/api/v1/rule-sets/{id}/lab-test` | Prueba el conjunto de reglas **de verdad** en un Asterion Lab efímero (ver abajo) |

Formato de un `Report`:

```json
{
  "analyzed_at": "2026-08-28T00:32:21Z",
  "backend": "application-firewall",
  "present": ["pf", "application-firewall"],
  "readable": true,
  "os": "darwin",
  "score": 65,
  "findings": [
    {
      "severity": "high",
      "title": "Application Firewall desactivada",
      "detail": "...",
      "recommendation": "..."
    }
  ],
  "raw_summary": "Firewall is disabled. (State = 0)\n..."
}
```

## Reglas de firewall, probadas de verdad en un Lab

Además de analizar el firewall real de esta máquina, el plugin deja
**declarar** reglas propias (mismo vocabulario que
`asterion-lab/spec.FirewallRule`: `action` allow/deny, `port`, `proto`
tcp/udp) y probarlas contra algo real antes de confiar en ellas —
`POST /api/v1/rule-sets/{id}/lab-test` genera un `lab.yaml` efímero (el
mismo patrón de dos VMs documentado en `asterion-core/README.md`: un
`server` Ubuntu con las reglas aplicadas por `ufw` real, un `client`
Alpine que las prueba con `nc` real) y ejecuta, vía el binario `asterion`
ya instalado, `lab create` → `lab start` → `lab test` → `lab destroy` —
siempre destruye al final, nunca deja una VM huérfana corriendo.

**Detalle no obvio, encontrado probando en vivo**: antes de cada prueba de
conectividad, se arranca un listener real (`python3 -m http.server
<puerto>`) en el puerto del server — sin esto, `allow` y `deny` dan el
mismo resultado (timeout) contra un puerto sin nada escuchando, y la
prueba no distinguiría "bloqueado por ufw" de "no hay nada ahí". Con el
listener real, un `allow` reachable prueba que ufw efectivamente dejó
pasar tráfico a un servicio real, y un `deny` bloqueado prueba que ufw lo
frenó pese a que sí había algo escuchando — no un falso positivo.

Es lento de verdad (boot real de VM + instalación de ufw por SSH, del
orden de 30-90s) — el endpoint no finge progreso, tarda lo que tarda un
laboratorio real (timeout de 5 minutos en el lado del plugin).

## Frontend propio

`frontend/` es una app React + Vite + pnpm independiente que consume esta
misma API: sparkline de puntaje en el tiempo y barras de severidad por
hallazgo (SVG a mano, sin librería de gráficos), más una sección de
Reglas de firewall (tabla de rule-sets, modal de alta/edición, botón
"Probar en un Lab" con su estado de espera). El binario Go **también
sirve su propio build** (`frontend/dist/`, vía `frontend_dist` en la
config — default `./frontend/dist`) en `/`, igual que `backend-core`
sirve `frontend-core`. Esto no es decorativo: el reverse proxy de
`backend-core` (`GET /api/plugins/{name}/proxy/{path}`) ya reenvía
cualquier método/contenido tal cual al puerto del plugin — **el dashboard
propio de este plugin ya está embebido de verdad** en el dashboard local
de Asterion (tab Plugins → este plugin → "Abrir panel"), sin código nuevo
de proxy: el único cambio necesario fue que `frontend/src/lib/api.ts` use
rutas relativas (sin barra inicial) para que el mismo build funcione
standalone y embebido.

### Desarrollo

```bash
# Terminal 1 — API
go run .   # ASTERION_PLUGIN_PORT=8081 por default si no se define

# Terminal 2 — frontend con hot reload, proxyea /api al puerto de arriba
cd frontend && PLUGIN_PORT=8081 pnpm dev
```

### Build de producción

```bash
cd frontend && pnpm install && pnpm build   # genera frontend/dist
cd .. && go build -o asterion-firewall-analysis .
./asterion-firewall-analysis   # sirve dashboard + API en un solo puerto
```

## Config (variables `ASTERION_PLUGIN_CONFIG_*`)

| Clave | Default | Qué es |
|---|---|---|
| `data_dir` | `./data` | Dónde vive `history.json` |
| `frontend_dist` | `./frontend/dist` | Dónde está el build del frontend |

## `plugin.yaml` — generado, no editado a mano

`plugin.yaml` ya existe y ya está declarado (resources, actions,
permissions) — su fuente editable es **`plugin.ast`**, compilado con:

```bash
asterion plugin from-ast plugin.ast --out . --force
```

`asterion plugin from-ast` (repo hermano `asterion-language`, paquete
`pluginmanifest`) valida el resultado en el momento. Para agregar un
resource o una action nueva: editar `plugin.ast`, no `plugin.yaml` directo.

## Qué falta (fase siguiente, a propósito no incluida acá)

- Analizadores de reglas nft/iptables más precisos que la heurística de
  texto actual.

## Verificación en vivo

Corrido de verdad contra el firewall real de esta máquina (macOS): detectó
`pf` + `application-firewall` presentes, leyó el estado real (Application
Firewall apagada, modo sigiloso apagado), generó 2 hallazgos con
severidad/recomendación, puntaje 65/100 — consistente con lo que
`asterion local doctor` reporta para la misma máquina. `POST
/api/v1/analysis` + `GET /api/v1/history` probados end-to-end. El binario
sirviendo su propio frontend build probado con `curl` (HTML en `/`, JS con
`content-type: text/javascript` en `/assets/...`, API intacta en
`/api/v1/*`).

**Lab test, contra QEMU real en esta máquina**: rule-set con una regla
`allow 8080/tcp` y una `deny 9090/tcp`, corrido de punta a punta vía
`POST /api/v1/rule-sets/{id}/lab-test`. Resultado real: `8080` alcanzable
desde la VM cliente (`nc` devolvió `open`), `9090` bloqueado (`nc`
timeout) **pese a tener un servidor real escuchando ahí** — confirmando
que es `ufw` bloqueando de verdad, no simplemente "no hay nada". Duración
real ~40s. `asterion lab list` después de la corrida: ninguna VM
huérfana.
