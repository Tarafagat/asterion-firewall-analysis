// Package rules guarda conjuntos de reglas de firewall definidos por el
// usuario ("rule sets") — mismo vocabulario exacto que
// asterion-lab/spec.FirewallRule (Action allow|deny, Port, Proto) para que
// una regla creada acá signifique lo mismo que una declarada a mano en un
// lab.yaml. No se importa ese paquete (los plugins nunca dependen de repos
// hermanos de asterion-core, se integran por CLI — ver internal/labtest):
// es un tipo propio que replica el mismo shape a propósito.
package rules

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type Rule struct {
	Action      string `json:"action"` // "allow" | "deny"
	Port        int    `json:"port"`
	Proto       string `json:"proto,omitempty"` // "tcp" | "udp", default tcp
	Description string `json:"description,omitempty"`
}

type RuleSet struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Rules     []Rule    `json:"rules"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var ErrNotFound = errors.New("conjunto de reglas no encontrado")

type Store struct {
	mu   sync.Mutex
	path string
}

func New(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(dataDir, "rule_sets.json")}, nil
}

func (s *Store) load() (map[string]RuleSet, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return map[string]RuleSet{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out map[string]RuleSet
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) save(sets map[string]RuleSet) error {
	data, err := json.MarshalIndent(sets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

func (s *Store) List() ([]RuleSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sets, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]RuleSet, 0, len(sets))
	for _, rs := range sets {
		out = append(out, rs)
	}
	return out, nil
}

func (s *Store) Get(id string) (RuleSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sets, err := s.load()
	if err != nil {
		return RuleSet{}, err
	}
	rs, ok := sets[id]
	if !ok {
		return RuleSet{}, ErrNotFound
	}
	return rs, nil
}

func (s *Store) Create(rs RuleSet) (RuleSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sets, err := s.load()
	if err != nil {
		return RuleSet{}, err
	}
	now := time.Now().UTC()
	rs.ID = strconv.FormatInt(now.UnixNano(), 36)
	rs.CreatedAt = now
	rs.UpdatedAt = now
	sets[rs.ID] = rs
	if err := s.save(sets); err != nil {
		return RuleSet{}, err
	}
	return rs, nil
}

func (s *Store) Update(id string, rs RuleSet) (RuleSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sets, err := s.load()
	if err != nil {
		return RuleSet{}, err
	}
	existing, ok := sets[id]
	if !ok {
		return RuleSet{}, ErrNotFound
	}
	rs.ID = id
	rs.CreatedAt = existing.CreatedAt
	rs.UpdatedAt = time.Now().UTC()
	sets[id] = rs
	if err := s.save(sets); err != nil {
		return RuleSet{}, err
	}
	return rs, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sets, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := sets[id]; !ok {
		return ErrNotFound
	}
	delete(sets, id)
	return s.save(sets)
}
