// Package inspect detecta y lee el estado REAL del firewall de esta
// máquina. No importa asterion-core/internal/runtime (es un paquete
// `internal/`, así que Go ni lo permitiría desde otro módulo) — este
// plugin vive en su propio repo y corre como su propio proceso, así que
// repite las mismas técnicas de detección (binario en PATH, comandos
// estándar) en vez de depender del binario de Asterion Core en tiempo de
// ejecución. Es la misma decisión que ya toma dummy-fs-provider: un plugin
// es un programa independiente, no un plan de asterion-core.
package inspect

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Backend identifica qué mecanismo de firewall se inspeccionó.
type Backend string

const (
	BackendNone          Backend = "none"
	BackendPF            Backend = "pf"
	BackendApplicationFW Backend = "application-firewall"
	BackendUFW           Backend = "ufw"
	BackendNFTables      Backend = "nftables"
	BackendIPTables      Backend = "iptables"
	socketfilterfwPath           = "/usr/libexec/ApplicationFirewall/socketfilterfw"
)

// Result es la lectura cruda de un backend — analyze.Analyze la convierte
// en hallazgos legibles. Readable=false es un resultado válido y
// frecuente (ufw/nft/iptables/pf exigen root para consultar reglas): un
// falso "todo bien" sería peor que decir explícitamente "no pude leerlo".
type Result struct {
	Backend   Backend  `json:"backend"`
	Present   []string `json:"present"`  // qué backends existen en esta máquina
	Readable  bool     `json:"readable"` // si se pudo leer el backend elegido sin privilegios
	Detail    string   `json:"detail"`
	RawOutput string   `json:"raw_output,omitempty"`
	NeedsSudo bool     `json:"needs_sudo"`
	OS        string   `json:"os"`
}

// Inspect detecta qué backends existen y lee el que manda (mismo orden de
// prioridad que asterion-core: en macOS, Application Firewall antes que
// pf porque se puede leer sin root; en Linux, ufw > nftables > iptables).
func Inspect() Result {
	present := detectPresent()
	os_ := runtime.GOOS

	choose := func(name string) bool {
		for _, p := range present {
			if p == name {
				return true
			}
		}
		return false
	}

	switch {
	case choose(string(BackendApplicationFW)):
		return readApplicationFirewall(present, os_)
	case choose(string(BackendPF)):
		return readPF(present, os_)
	case choose(string(BackendUFW)):
		return readUFW(present, os_)
	case choose(string(BackendNFTables)):
		return readNFTables(present, os_)
	case choose(string(BackendIPTables)):
		return readIPTables(present, os_)
	default:
		return Result{Backend: BackendNone, Present: present, Readable: false, Detail: "no se detectó ningún firewall administrable conocido en esta máquina", OS: os_}
	}
}

func detectPresent() []string {
	if runtime.GOOS == "darwin" {
		found := []string{}
		if _, err := exec.LookPath("pfctl"); err == nil {
			found = append(found, string(BackendPF))
		}
		if _, err := os.Stat(socketfilterfwPath); err == nil {
			found = append(found, string(BackendApplicationFW))
		}
		return found
	}
	found := []string{}
	for _, b := range []struct {
		label, bin string
	}{
		{string(BackendUFW), "ufw"},
		{string(BackendNFTables), "nft"},
		{string(BackendIPTables), "iptables"},
	} {
		if _, err := exec.LookPath(b.bin); err == nil {
			found = append(found, b.label)
		}
	}
	return found
}

func needsPrivileges(err error, out string) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(out)
	return strings.Contains(lower, "root") || strings.Contains(lower, "permission denied") || strings.Contains(lower, "operation not permitted")
}

func readApplicationFirewall(present []string, os_ string) Result {
	out, err := exec.Command(socketfilterfwPath, "--getglobalstate").CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return Result{Backend: BackendApplicationFW, Present: present, Readable: false, Detail: "no se pudo consultar la Application Firewall: " + text, OS: os_}
	}
	var lines []string
	lines = append(lines, text)
	if o, err := exec.Command(socketfilterfwPath, "--getstealthmode").CombinedOutput(); err == nil {
		lines = append(lines, strings.TrimSpace(string(o)))
	}
	if o, err := exec.Command(socketfilterfwPath, "--getblockall").CombinedOutput(); err == nil {
		lines = append(lines, strings.TrimSpace(string(o)))
	}
	return Result{Backend: BackendApplicationFW, Present: present, Readable: true, RawOutput: strings.Join(lines, "\n"), OS: os_}
}

func readPF(present []string, os_ string) Result {
	out, err := exec.Command("pfctl", "-s", "info").CombinedOutput()
	text := string(out)
	if needsPrivileges(err, text) {
		return Result{Backend: BackendPF, Present: present, Readable: false, NeedsSudo: true, Detail: "pf necesita privilegios de root para leer /dev/pf — corré este plugin con sudo para un análisis completo", OS: os_}
	}
	if err != nil {
		return Result{Backend: BackendPF, Present: present, Readable: false, Detail: "no se pudo consultar pf: " + strings.TrimSpace(text), OS: os_}
	}
	return Result{Backend: BackendPF, Present: present, Readable: true, RawOutput: strings.TrimSpace(text), OS: os_}
}

func readUFW(present []string, os_ string) Result {
	out, err := exec.Command("ufw", "status", "verbose").CombinedOutput()
	text := string(out)
	if needsPrivileges(err, text) {
		return Result{Backend: BackendUFW, Present: present, Readable: false, NeedsSudo: true, Detail: "ufw necesita privilegios de root para consultar el estado real — corré este plugin con sudo", OS: os_}
	}
	if err != nil {
		return Result{Backend: BackendUFW, Present: present, Readable: false, Detail: "no se pudo consultar ufw: " + strings.TrimSpace(text), OS: os_}
	}
	return Result{Backend: BackendUFW, Present: present, Readable: true, RawOutput: strings.TrimSpace(text), OS: os_}
}

func readNFTables(present []string, os_ string) Result {
	out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	text := string(out)
	if needsPrivileges(err, text) {
		return Result{Backend: BackendNFTables, Present: present, Readable: false, NeedsSudo: true, Detail: "nftables necesita privilegios de root para listar el ruleset — corré este plugin con sudo", OS: os_}
	}
	if err != nil {
		return Result{Backend: BackendNFTables, Present: present, Readable: false, Detail: "no se pudo consultar nftables: " + strings.TrimSpace(text), OS: os_}
	}
	return Result{Backend: BackendNFTables, Present: present, Readable: true, RawOutput: strings.TrimSpace(text), OS: os_}
}

func readIPTables(present []string, os_ string) Result {
	out, err := exec.Command("iptables", "-L", "-n").CombinedOutput()
	text := string(out)
	if needsPrivileges(err, text) {
		return Result{Backend: BackendIPTables, Present: present, Readable: false, NeedsSudo: true, Detail: "iptables necesita privilegios de root para listar reglas — corré este plugin con sudo", OS: os_}
	}
	if err != nil {
		return Result{Backend: BackendIPTables, Present: present, Readable: false, Detail: "no se pudo consultar iptables: " + strings.TrimSpace(text), OS: os_}
	}
	return Result{Backend: BackendIPTables, Present: present, Readable: true, RawOutput: strings.TrimSpace(text), OS: os_}
}
