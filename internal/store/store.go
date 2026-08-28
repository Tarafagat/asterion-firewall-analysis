// Package store guarda el historial de análisis en un único archivo JSON
// local — "básico" a propósito (mismo criterio que el nombre del plugin de
// mail hermano): sin base de datos, sin dependencias externas, algo que
// cualquiera pueda leer con 'cat' si hace falta debuggear.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"asterion-firewall-analysis/internal/analyze"
)

const maxHistory = 100

type Store struct {
	mu   sync.Mutex
	path string
}

func New(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(dataDir, "history.json")}, nil
}

func (s *Store) load() ([]analyze.Report, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var reports []analyze.Report
	if err := json.Unmarshal(data, &reports); err != nil {
		return nil, err
	}
	return reports, nil
}

// Append agrega un reporte al historial (más reciente primero) y trunca a
// maxHistory — no queremos que el archivo crezca sin límite si alguien deja
// un cron pegándole a /analyze cada minuto.
func (s *Store) Append(r analyze.Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	reports, err := s.load()
	if err != nil {
		return err
	}
	reports = append([]analyze.Report{r}, reports...)
	if len(reports) > maxHistory {
		reports = reports[:maxHistory]
	}
	data, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

func (s *Store) History(limit int) ([]analyze.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	reports, err := s.load()
	if err != nil {
		return nil, err
	}
	if limit > 0 && limit < len(reports) {
		reports = reports[:limit]
	}
	return reports, nil
}
