// Package labtest prueba un rules.RuleSet DE VERDAD contra un Asterion Lab
// efímero — VMs QEMU reales, ufw real, tráfico de red real dentro de la
// red privada del laboratorio. No reimplementa nada de eso (mismo criterio
// que backend-core/app/plugin_bridge.py): le pide al binario `asterion` ya
// instalado que cree, arranque, pruebe y destruya el laboratorio, y
// devuelve tal cual el resultado real de 'asterion lab test'.
package labtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"asterion-firewall-analysis/internal/rules"
)

// TestResult replica asterion-lab/testrun.TestResult campo a campo — tipo
// propio en vez de importar ese módulo (los plugins se integran con
// asterion-core y sus repos hermanos por CLI, nunca como dependencia Go
// directa, ver internal/rules).
type TestResult struct {
	Name      string `json:"name"`
	VM        string `json:"vm"`
	Run       string `json:"run"`
	Output    string `json:"output"`
	ExitCode  int    `json:"exit_code"`
	Passed    bool   `json:"passed"`
	FailedWhy string `json:"failed_why,omitempty"`
}

type Result struct {
	LabName string       `json:"lab_name"`
	Passed  bool         `json:"passed"`
	Results []TestResult `json:"results"`
}

const (
	serverIP = "10.77.0.10"
	clientIP = "10.77.0.11"
)

func findAsterionBinary() (string, error) {
	if p := os.Getenv("ASTERION_BIN"); p != "" {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}
	p, err := exec.LookPath("asterion")
	if err != nil {
		return "", fmt.Errorf("no encontré el binario 'asterion' en PATH ni en ASTERION_BIN — hace falta para poder probar reglas en un Lab de verdad")
	}
	return p, nil
}

func randomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// buildLabYAML arma el YAML del laboratorio efímero — mismo patrón exacto
// probado en vivo y documentado en asterion-core/README.md: una VM
// "server" (ubuntu-24.04 — asterion-lab/firewall.Apply instala ufw vía
// apt-get, así que tiene que ser una imagen Debian/Ubuntu) con las reglas
// del set, una VM "client" (alpine-3.20) que las prueba de verdad con 'nc'.
// El puerto 22 siempre se permite explícitamente primero: si no,
// 'asterion lab test' no podría ni conectarse por SSH para correr el resto
// de las pruebas.
func buildLabYAML(labName string, rs rules.RuleSet) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: asterion.dev/v1\nkind: Lab\nname: %s\n", labName)
	fmt.Fprintf(&b, "network:\n  name: %s-net\n  cidr: 10.77.0.0/24\n", labName)
	b.WriteString("vms:\n")
	fmt.Fprintf(&b, "  - name: server\n    image: ubuntu-24.04\n    ip: %s\n", serverIP)
	b.WriteString("    firewall:\n      backend: ufw\n      rules:\n")
	b.WriteString("        - {action: allow, port: 22, proto: tcp}\n")
	for _, r := range rs.Rules {
		proto := r.Proto
		if proto == "" {
			proto = "tcp"
		}
		fmt.Fprintf(&b, "        - {action: %s, port: %d, proto: %s}\n", r.Action, r.Port, proto)
	}
	fmt.Fprintf(&b, "  - name: client\n    image: alpine-3.20\n    ip: %s\n", clientIP)

	b.WriteString("tests:\n")
	for i, r := range rs.Rules {
		proto := r.Proto
		if proto == "" {
			proto = "tcp"
		}
		name := r.Description
		if name == "" {
			name = fmt.Sprintf("%s %d/%s", r.Action, r.Port, proto)
		}
		name = strings.ReplaceAll(name, `"`, "'")
		expect := 0
		if r.Action == "deny" {
			expect = 1
		}
		ncFlags := "-zvw3"
		if proto == "udp" {
			ncFlags = "-uzvw3"
		}

		// Paso de setup: arranca un listener real en 'server' antes de
		// probar la conectividad — sin esto, 'allow' y 'deny' dan el mismo
		// resultado (timeout) contra un puerto sin nada escuchando, y la
		// prueba no distingue "bloqueado por ufw" de "no hay nada ahí".
		// python3 viene en cualquier imagen cloud-init de Ubuntu (lo
		// necesita el propio cloud-init para arrancar), así que no
		// depende de instalar nada nuevo.
		var listenCmd string
		if proto == "udp" {
			listenCmd = fmt.Sprintf(
				"python3 -c \\\"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', %d)); s.recvfrom(1024)\\\"",
				r.Port,
			)
		} else {
			listenCmd = fmt.Sprintf("python3 -m http.server %d --bind 0.0.0.0", r.Port)
		}
		fmt.Fprintf(&b, "  - name: \"regla %d: preparar listener en %d/%s\"\n", i+1, r.Port, proto)
		b.WriteString("    vm: server\n")
		fmt.Fprintf(&b, "    run: \"nohup %s >/tmp/listener-%d.log 2>&1 & sleep 1 ; echo started\"\n", listenCmd, r.Port)
		b.WriteString("    expect: {contains: \"started\"}\n")

		fmt.Fprintf(&b, "  - name: \"regla %d: %s\"\n", i+1, name)
		b.WriteString("    vm: client\n")
		fmt.Fprintf(&b, "    run: \"nc %s %s %d\"\n", ncFlags, serverIP, r.Port)
		fmt.Fprintf(&b, "    expect: {exit_code: %d}\n", expect)
	}
	return b.String()
}

// Run crea, arranca, prueba y destruye el laboratorio efímero — en ese
// orden, siempre destruyendo al final (incluso si algo falló a mitad de
// camino) para no dejar una VM huérfana corriendo. Es lento de verdad
// (boot real + instalación de ufw por SSH, ~30-90s en esta clase de
// hardware) — timeout generoso en vez de progreso fingido.
func Run(ctx context.Context, rs rules.RuleSet) (Result, error) {
	bin, err := findAsterionBinary()
	if err != nil {
		return Result{}, err
	}
	if len(rs.Rules) == 0 {
		return Result{}, fmt.Errorf("el conjunto de reglas %q no tiene ninguna regla para probar", rs.Name)
	}

	labName := "fw-test-" + randomSuffix()
	yamlContent := buildLabYAML(labName, rs)

	tmpFile, err := os.CreateTemp("", "asterion-fw-lab-*.yaml")
	if err != nil {
		return Result{}, fmt.Errorf("no pude crear el archivo temporal del laboratorio: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, err := tmpFile.WriteString(yamlContent); err != nil {
		tmpFile.Close()
		return Result{}, fmt.Errorf("no pude escribir el YAML del laboratorio: %w", err)
	}
	tmpFile.Close()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	created := false
	defer func() {
		if !created {
			return
		}
		destroyCtx, destroyCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer destroyCancel()
		_ = exec.CommandContext(destroyCtx, bin, "lab", "destroy", labName).Run()
	}()

	if out, err := exec.CommandContext(ctx, bin, "lab", "create", tmpPath).CombinedOutput(); err != nil {
		return Result{}, fmt.Errorf("'asterion lab create' falló: %w (salida: %s)", err, strings.TrimSpace(string(out)))
	}
	created = true

	if out, err := exec.CommandContext(ctx, bin, "lab", "start", labName, "--json").CombinedOutput(); err != nil {
		return Result{}, fmt.Errorf("'asterion lab start' falló: %w (salida: %s)", err, strings.TrimSpace(string(out)))
	}

	var stdout, stderr bytes.Buffer
	testCmd := exec.CommandContext(ctx, bin, "lab", "test", labName)
	testCmd.Stdout = &stdout
	testCmd.Stderr = &stderr
	_ = testCmd.Run() // exit code no-cero solo indica "algún test falló" — ya queda reflejado por-fila en Passed

	var results []TestResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		return Result{}, fmt.Errorf("no pude interpretar la salida de 'asterion lab test': %s", detail)
	}

	passed := true
	for _, r := range results {
		if !r.Passed {
			passed = false
			break
		}
	}
	return Result{LabName: labName, Passed: passed, Results: results}, nil
}
