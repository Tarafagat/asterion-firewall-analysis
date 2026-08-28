// Package analyze es el valor agregado real de este plugin sobre lo que
// asterion-core ya hace: inspect.Result es un dato crudo (texto de
// pfctl/ufw/nft/iptables); acá se convierte en hallazgos concretos con
// severidad y recomendación, y un puntaje 0-100. asterion-core (ver
// 'asterion local doctor') se detiene en el dato crudo a propósito —
// interpretarlo es justo lo que un plugin opinático puede hacer sin
// esperar un release del core cada vez que cambia un criterio.
package analyze

import (
	"regexp"
	"strings"
	"time"

	"asterion-firewall-analysis/internal/inspect"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Detail         string   `json:"detail"`
	Recommendation string   `json:"recommendation,omitempty"`
}

type Report struct {
	AnalyzedAt time.Time       `json:"analyzed_at"`
	Backend    inspect.Backend `json:"backend"`
	Present    []string        `json:"present"`
	Readable   bool            `json:"readable"`
	OS         string          `json:"os"`
	Score      int             `json:"score"` // 0 (crítico) - 100 (sin hallazgos)
	Findings   []Finding       `json:"findings"`
	RawSummary string          `json:"raw_summary,omitempty"`
}

var severityPenalty = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      5,
	SeverityMedium:   15,
	SeverityHigh:     30,
	SeverityCritical: 50,
}

// sensitivePorts son puertos que, si aparecen abiertos a cualquier IP
// (0.0.0.0/0 o "Anywhere"), ameritan una alerta más fuerte que "hay un
// puerto abierto" — son los que un atacante prueba primero.
var sensitivePorts = map[string]string{
	"22":    "SSH",
	"23":    "Telnet",
	"3389":  "RDP",
	"3306":  "MySQL",
	"5432":  "PostgreSQL",
	"6379":  "Redis",
	"27017": "MongoDB",
	"9200":  "Elasticsearch",
	"9092":  "Kafka",
	"5900":  "VNC",
}

// Analyze corre inspect.Inspect() y arma el reporte. Separado de Inspect()
// para poder testear el parsing con un inspect.Result armado a mano, sin
// depender de qué firewall tenga la máquina que corre el test.
func Analyze(r inspect.Result) Report {
	report := Report{
		AnalyzedAt: time.Now().UTC(),
		Backend:    r.Backend,
		Present:    r.Present,
		Readable:   r.Readable,
		OS:         r.OS,
		RawSummary: shortSummary(r.RawOutput),
	}

	if len(r.Present) == 0 {
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityCritical,
			Title:    "Ningún firewall administrable detectado",
			Detail:   "No se encontró pf, Application Firewall, ufw, nftables ni iptables en esta máquina.",
			Recommendation: "Instalá y activá al menos uno — en macOS alcanza con activar la Application Firewall " +
				"(System Settings → Network → Firewall); en Linux, 'sudo apt install ufw && sudo ufw enable' o equivalente.",
		})
		report.Score = 0
		return report
	}

	if !r.Readable {
		report.Findings = append(report.Findings, Finding{
			Severity:       SeverityMedium,
			Title:          "No se pudo leer el estado real del firewall",
			Detail:         r.Detail,
			Recommendation: "Si el motivo es falta de privilegios, corré este plugin con más permisos para un análisis completo — sin eso, este reporte es parcial, no un 'todo bien'.",
		})
		report.Score = clampScore(70)
		return report
	}

	switch r.Backend {
	case inspect.BackendApplicationFW:
		report.Findings = append(report.Findings, analyzeApplicationFirewall(r.RawOutput)...)
	case inspect.BackendPF:
		report.Findings = append(report.Findings, analyzePF(r.RawOutput)...)
	case inspect.BackendUFW:
		report.Findings = append(report.Findings, analyzeUFW(r.RawOutput)...)
	case inspect.BackendNFTables, inspect.BackendIPTables:
		report.Findings = append(report.Findings, analyzeRuleText(r.RawOutput)...)
	}

	if len(report.Findings) == 0 {
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityInfo,
			Title:    "Sin hallazgos",
			Detail:   "No se encontraron problemas evidentes en la configuración leída.",
		})
	}

	report.Score = scoreFrom(report.Findings)
	return report
}

func scoreFrom(findings []Finding) int {
	score := 100
	for _, f := range findings {
		score -= severityPenalty[f.Severity]
	}
	return clampScore(score)
}

func clampScore(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

func analyzeApplicationFirewall(raw string) []Finding {
	var findings []Finding
	lower := strings.ToLower(raw)

	if strings.Contains(lower, "disabled") && strings.Contains(lower, "state = 0") {
		findings = append(findings, Finding{
			Severity:       SeverityHigh,
			Title:          "Application Firewall desactivada",
			Detail:         "El firewall de aplicaciones de macOS está apagado — cualquier proceso puede aceptar conexiones entrantes sin que el sistema pregunte.",
			Recommendation: "System Settings → Network → Firewall → activarlo, o 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'.",
		})
	}
	if strings.Contains(lower, "stealth mode is off") {
		findings = append(findings, Finding{
			Severity:       SeverityLow,
			Title:          "Modo sigiloso desactivado",
			Detail:         "Esta máquina responde a intentos de ping/escaneo de puertos aunque nada esté escuchando — más fácil de descubrir en una red compartida.",
			Recommendation: "'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on'.",
		})
	}
	return findings
}

// pfEnabled matchea "Status: Enabled" de `pfctl -s info` (mayúscula fija
// del comando real, no una entrada de usuario).
var pfStatusRe = regexp.MustCompile(`(?i)status:\s*(enabled|disabled)`)

func analyzePF(raw string) []Finding {
	m := pfStatusRe.FindStringSubmatch(raw)
	if len(m) == 2 && strings.EqualFold(m[1], "disabled") {
		return []Finding{{
			Severity:       SeverityHigh,
			Title:          "pf desactivado",
			Detail:         "El packet filter (pf) está apagado a nivel de sistema.",
			Recommendation: "'sudo pfctl -e' lo activa — pero primero revisá que /etc/pf.conf tenga reglas razonables, activarlo sin reglas no filtra nada.",
		}}
	}
	return nil
}

// ufwPortLineRe matchea líneas de 'ufw status verbose' del tipo:
// "22/tcp                     ALLOW IN    Anywhere"
var ufwPortLineRe = regexp.MustCompile(`(?m)^(\d+)(?:/\w+)?\s+ALLOW\s+IN\s+Anywhere`)

func analyzeUFW(raw string) []Finding {
	var findings []Finding
	if strings.Contains(raw, "Status: inactive") {
		return []Finding{{
			Severity:       SeverityCritical,
			Title:          "ufw instalado pero inactivo",
			Detail:         "ufw está presente en el sistema pero no está filtrando nada ahora mismo.",
			Recommendation: "'sudo ufw enable' — revisá antes las reglas con 'sudo ufw status numbered' para no cortarte el propio acceso SSH.",
		}}
	}
	findings = append(findings, openPortFindings(ufwPortLineRe.FindAllStringSubmatch(raw, -1), 1)...)
	return findings
}

// genericPortRe es un intento heurístico, no un parser completo de
// iptables/nft — busca puertos conocidos mencionados junto a ACCEPT y
// 0.0.0.0/0 en la misma línea. Cubre el caso común; reglas más elaboradas
// (múltiples líneas, cadenas custom) quedan fuera de v1 a propósito, y el
// raw_summary siempre queda disponible para revisión manual.
func analyzeRuleText(raw string) []Finding {
	var findings []Finding
	for port, service := range sensitivePorts {
		re := regexp.MustCompile(`(?m).*\b` + port + `\b.*`)
		for _, line := range re.FindAllString(raw, -1) {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "accept") && (strings.Contains(line, "0.0.0.0/0") || strings.Contains(lower, "anywhere")) {
				findings = append(findings, Finding{
					Severity:       severityForPort(port),
					Title:          "Puerto " + port + " (" + service + ") abierto a cualquier IP",
					Detail:         strings.TrimSpace(line),
					Recommendation: "Restringí el origen a IPs/rangos conocidos si este servicio no necesita estar expuesto a Internet.",
				})
				break
			}
		}
	}
	return findings
}

func openPortFindings(matches [][]string, portIdx int) []Finding {
	var findings []Finding
	for _, m := range matches {
		port := m[portIdx]
		service, known := sensitivePorts[port]
		if !known {
			continue
		}
		findings = append(findings, Finding{
			Severity:       severityForPort(port),
			Title:          "Puerto " + port + " (" + service + ") abierto a cualquier IP",
			Detail:         "ufw permite conexiones entrantes a " + port + " desde 'Anywhere'.",
			Recommendation: "Restringí el origen ('sudo ufw allow from <IP> to any port " + port + "') si no necesita estar expuesto a todo Internet.",
		})
	}
	return findings
}

func severityForPort(port string) Severity {
	switch port {
	case "22", "3389", "5900":
		return SeverityMedium // administrativo — grave si se descuida, pero a veces es intencional
	default:
		return SeverityHigh // bases de datos/colas expuestas directo casi nunca es intencional
	}
}

func shortSummary(raw string) string {
	if raw == "" {
		return ""
	}
	lines := strings.Split(raw, "\n")
	if len(lines) <= 6 {
		return raw
	}
	return strings.Join(lines[:6], "\n") + "\n…"
}
