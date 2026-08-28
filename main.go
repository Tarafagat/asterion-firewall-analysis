// Command asterion-firewall-analysis analiza el firewall real de la
// máquina donde corre (no un mock, no una lista fija) y devuelve hallazgos
// con severidad y recomendación, no solo "está prendido o apagado" — eso
// último ya lo hace asterion-core ('asterion local doctor'). Ver README.md
// para la decisión de diseño completa.
package main

import (
	"log"
	"net/http"

	"github.com/Tarafagat/asterion-plugin-contract/apc"
	"github.com/Tarafagat/asterion-plugin-contract/sdk/go/pdk"

	"asterion-firewall-analysis/internal/httpapi"
	"asterion-firewall-analysis/internal/rules"
	"asterion-firewall-analysis/internal/store"
)

func main() {
	cfg := pdk.Config()
	dataDir := pdk.ConfigString(cfg, "data_dir", "./data")

	st, err := store.New(dataDir)
	if err != nil {
		log.Fatalf("no pude preparar el historial en %s: %v", dataDir, err)
	}
	rs, err := rules.New(dataDir)
	if err != nil {
		log.Fatalf("no pude preparar el almacenamiento de reglas en %s: %v", dataDir, err)
	}

	logger := pdk.NewLogger(nameOr(pdk.Name(), "asterion-firewall-analysis"))
	distDir := pdk.ConfigString(cfg, "frontend_dist", "./frontend/dist")

	// Se usa para el fallback de frontend (ver pdk.MountFrontend) si algún
	// día frontend/dist no estuviera.
	pluginDir := pdk.Dir()
	if pluginDir == "" {
		pluginDir = "."
	}
	manifest, err := apc.LoadManifest(pluginDir)
	if err != nil {
		logger.Warn("no pude leer plugin.yaml propio (solo afecta el frontend autogenerado de respaldo)", map[string]any{"error": err.Error()})
	}

	server := httpapi.New(st, rs, logger, distDir, manifest)

	port := pdk.Port()
	if port == "" {
		port = "8081"
	}

	logger.Info("arrancando", map[string]any{"port": port, "data_dir": dataDir})
	if err := http.ListenAndServe("127.0.0.1:"+port, server.Mux()); err != nil {
		log.Fatal(err)
	}
}

func nameOr(name, fallback string) string {
	if name == "" {
		return fallback
	}
	return name
}
