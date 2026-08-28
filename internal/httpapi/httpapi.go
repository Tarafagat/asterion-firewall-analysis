// Package httpapi expone el análisis por HTTP — mismo estilo que
// dummy-fs-provider (net/http estándar, pdk para health/errores), para que
// enchufarle un plugin.yaml más adelante sea directo: los endpoints ya
// están pensados como los futuros "resources"/"actions" del contrato.
package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Tarafagat/asterion-plugin-contract/apc"
	"github.com/Tarafagat/asterion-plugin-contract/sdk/go/pdk"

	"asterion-firewall-analysis/internal/analyze"
	"asterion-firewall-analysis/internal/inspect"
	"asterion-firewall-analysis/internal/labtest"
	"asterion-firewall-analysis/internal/rules"
	"asterion-firewall-analysis/internal/store"
)

type Server struct {
	store    *store.Store
	rules    *rules.Store
	logger   *pdk.Logger
	distDir  string
	manifest apc.Manifest
}

func New(st *store.Store, rs *rules.Store, logger *pdk.Logger, distDir string, manifest apc.Manifest) *Server {
	return &Server{store: st, rules: rs, logger: logger, distDir: distDir, manifest: manifest}
}

// Mux registra la API bajo /api/v1 y /health primero — Go 1.22+ ServeMux
// hace "el patrón más específico gana" independiente del orden de
// registro, así que esto no depende de qué se registre antes. Después
// monta el build de frontend/ en "/": mismo patrón que backend-core sirve
// frontend-core (ver Server.mount abajo) — así, el día que un plugin.yaml
// declare este puerto como embebible, GET /api/plugins/<name>/proxy/ ya
// sirve el dashboard propio de este plugin sin código nuevo (el reverse
// proxy de backend-core ya reenvía cualquier método/contenido tal cual).
func (s *Server) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", pdk.HealthHandler(s.health))
	mux.HandleFunc("GET /api/v1/analysis", s.getLatestAnalysis)
	mux.HandleFunc("POST /api/v1/analysis", s.runAnalysis)
	mux.HandleFunc("GET /api/v1/history", s.getHistory)
	mux.HandleFunc("GET /api/v1/rule-sets", s.listRuleSets)
	mux.HandleFunc("POST /api/v1/rule-sets", s.createRuleSet)
	mux.HandleFunc("GET /api/v1/rule-sets/{id}", s.getRuleSet)
	mux.HandleFunc("PUT /api/v1/rule-sets/{id}", s.updateRuleSet)
	mux.HandleFunc("DELETE /api/v1/rule-sets/{id}", s.deleteRuleSet)
	mux.HandleFunc("POST /api/v1/rule-sets/{id}/lab-test", s.labTestRuleSet)
	s.mountFrontend(mux)
	return mux
}

// mountFrontend delega en el Plugin Contract (pdk.MountFrontend): sirve
// frontend/dist si existe, y si no genera y sirve una página de
// documentación a partir del propio manifest.
func (s *Server) mountFrontend(mux *http.ServeMux) {
	pdk.MountFrontend(mux, s.distDir, s.manifest)
}

func (s *Server) health() (pdk.Status, string) {
	return pdk.Healthy, ""
}

// getLatestAnalysis corre un análisis fresco pero NO lo guarda en el
// historial — es la acción de "solo lectura" (resource), separada de
// runAnalysis (action explícita) para que ver el estado actual nunca
// dependa de acordarse de limpiar el historial después.
func (s *Server) getLatestAnalysis(w http.ResponseWriter, r *http.Request) {
	report := analyze.Analyze(inspect.Inspect())
	writeJSON(w, report)
}

// runAnalysis corre un análisis y lo persiste en el historial — pensado
// como la "action" (ej. desde un botón "Analizar ahora" o un cron).
func (s *Server) runAnalysis(w http.ResponseWriter, r *http.Request) {
	report := analyze.Analyze(inspect.Inspect())
	if err := s.store.Append(report); err != nil {
		pdk.WriteError(w, http.StatusInternalServerError, "no pude guardar el análisis en el historial", err.Error())
		return
	}
	s.logger.Info("analysis.completed", map[string]any{
		"backend": report.Backend, "score": report.Score, "findings": len(report.Findings),
	})
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, report)
}

func (s *Server) getHistory(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	history, err := s.store.History(limit)
	if err != nil {
		pdk.WriteError(w, http.StatusInternalServerError, "no pude leer el historial", err.Error())
		return
	}
	writeJSON(w, history)
}

func (s *Server) listRuleSets(w http.ResponseWriter, r *http.Request) {
	sets, err := s.rules.List()
	if err != nil {
		pdk.WriteError(w, http.StatusInternalServerError, "no pude listar los conjuntos de reglas", err.Error())
		return
	}
	writeJSON(w, sets)
}

func (s *Server) createRuleSet(w http.ResponseWriter, r *http.Request) {
	var in rules.RuleSet
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		pdk.WriteError(w, http.StatusBadRequest, "cuerpo inválido", err.Error())
		return
	}
	if in.Name == "" || len(in.Rules) == 0 {
		pdk.WriteError(w, http.StatusBadRequest, "'name' y al menos una regla en 'rules' son obligatorios", "")
		return
	}
	created, err := s.rules.Create(in)
	if err != nil {
		pdk.WriteError(w, http.StatusInternalServerError, "no pude guardar el conjunto de reglas", err.Error())
		return
	}
	s.logger.Info("rule_set.created", map[string]any{"id": created.ID, "name": created.Name, "rules": len(created.Rules)})
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, created)
}

func (s *Server) getRuleSet(w http.ResponseWriter, r *http.Request) {
	rs, err := s.rules.Get(r.PathValue("id"))
	if err != nil {
		pdk.WriteError(w, http.StatusNotFound, "no existe ese conjunto de reglas", "")
		return
	}
	writeJSON(w, rs)
}

func (s *Server) updateRuleSet(w http.ResponseWriter, r *http.Request) {
	var in rules.RuleSet
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		pdk.WriteError(w, http.StatusBadRequest, "cuerpo inválido", err.Error())
		return
	}
	updated, err := s.rules.Update(r.PathValue("id"), in)
	if err != nil {
		pdk.WriteError(w, http.StatusNotFound, "no existe ese conjunto de reglas", "")
		return
	}
	s.logger.Info("rule_set.updated", map[string]any{"id": updated.ID})
	writeJSON(w, updated)
}

func (s *Server) deleteRuleSet(w http.ResponseWriter, r *http.Request) {
	if err := s.rules.Delete(r.PathValue("id")); err != nil {
		pdk.WriteError(w, http.StatusNotFound, "no existe ese conjunto de reglas", "")
		return
	}
	s.logger.Info("rule_set.deleted", map[string]any{"id": r.PathValue("id")})
	w.WriteHeader(http.StatusNoContent)
}

// labTestRuleSet prueba el conjunto de reglas DE VERDAD en un Asterion Lab
// efímero (VMs QEMU reales) — lento (boot real + SSH + apt-get, del orden
// de 30-90s), así que esto no finge progreso, simplemente tarda lo que
// tarda un laboratorio real.
func (s *Server) labTestRuleSet(w http.ResponseWriter, r *http.Request) {
	rs, err := s.rules.Get(r.PathValue("id"))
	if err != nil {
		pdk.WriteError(w, http.StatusNotFound, "no existe ese conjunto de reglas", "")
		return
	}
	result, err := labtest.Run(r.Context(), rs)
	if err != nil {
		pdk.WriteError(w, http.StatusBadGateway, "no pude probar las reglas en un Lab", err.Error())
		return
	}
	s.logger.Info("rule_set.lab_tested", map[string]any{
		"id": rs.ID, "lab_name": result.LabName, "passed": result.Passed, "tests": len(result.Results),
	})
	writeJSON(w, result)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
