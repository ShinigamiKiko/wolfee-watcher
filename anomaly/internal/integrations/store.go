package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	KindJira       = "jira"
	KindMattermost = "mattermost"
	KindHarbor     = "harbor"
)

type JiraConfig struct {
	URL       string `json:"url"`
	Email     string `json:"email,omitempty"`
	Token     string `json:"token"`
	ProjectID string `json:"project"`
	IssueType string `json:"issue_type,omitempty"`
}

type MattermostConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel,omitempty"`
	Username   string `json:"username,omitempty"`
}

type HarborConfig struct {
	URL      string `json:"url"`
	Username string `json:"username,omitempty"`
	Token    string `json:"token"`
}

type Record struct {
	Kind      string          `json:"kind"`
	Enabled   bool            `json:"enabled"`
	Config    json.RawMessage `json:"config"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type Store struct {
	pool *pgxpool.Pool
	mu   sync.RWMutex
	cfg  map[string]Record
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, cfg: make(map[string]Record)}
}

func (s *Store) Load(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT kind, enabled, config, updated_at FROM integrations`)
	if err != nil {
		return err
	}
	defer rows.Close()

	next := make(map[string]Record)
	for rows.Next() {
		var r Record
		var raw []byte
		if err := rows.Scan(&r.Kind, &r.Enabled, &raw, &r.UpdatedAt); err != nil {
			return err
		}
		r.Config = raw
		next[r.Kind] = r
	}
	s.mu.Lock()
	s.cfg = next
	s.mu.Unlock()
	return nil
}

func (s *Store) Get(kind string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.cfg[kind]
	return r, ok
}

func (s *Store) All() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0, len(s.cfg))
	for _, r := range s.cfg {
		out = append(out, r)
	}
	return out
}

func (s *Store) Upsert(ctx context.Context, kind string, enabled bool, cfg json.RawMessage) (Record, error) {
	if !validKind(kind) {
		return Record{}, fmt.Errorf("unknown kind %q", kind)
	}
	if len(cfg) == 0 {
		cfg = json.RawMessage("{}")
	}
	var updatedAt time.Time
	err := s.pool.QueryRow(ctx, `
		INSERT INTO integrations (kind, enabled, config, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (kind) DO UPDATE
		SET enabled = EXCLUDED.enabled,
		    config  = EXCLUDED.config,
		    updated_at = NOW()
		RETURNING updated_at`, kind, enabled, []byte(cfg)).Scan(&updatedAt)
	if err != nil {
		return Record{}, err
	}
	r := Record{Kind: kind, Enabled: enabled, Config: cfg, UpdatedAt: updatedAt}
	s.mu.Lock()
	s.cfg[kind] = r
	s.mu.Unlock()
	return r, nil
}

func (s *Store) Delete(ctx context.Context, kind string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM integrations WHERE kind = $1`, kind); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.cfg, kind)
	s.mu.Unlock()
	return nil
}

func validKind(k string) bool {
	switch k {
	case KindJira, KindMattermost, KindHarbor:
		return true
	}
	return false
}

func (s *Store) JiraConfig() (JiraConfig, bool) {
	r, ok := s.Get(KindJira)
	if !ok || !r.Enabled {
		return JiraConfig{}, false
	}
	var c JiraConfig
	if err := json.Unmarshal(r.Config, &c); err != nil || c.URL == "" || c.ProjectID == "" {
		return JiraConfig{}, false
	}
	return c, true
}

func (s *Store) MattermostConfig() (MattermostConfig, bool) {
	r, ok := s.Get(KindMattermost)
	if !ok || !r.Enabled {
		return MattermostConfig{}, false
	}
	var c MattermostConfig
	if err := json.Unmarshal(r.Config, &c); err != nil || c.WebhookURL == "" {
		return MattermostConfig{}, false
	}
	return c, true
}

func (s *Store) HarborConfig() (HarborConfig, bool) {
	r, ok := s.Get(KindHarbor)
	if !ok {
		return HarborConfig{}, false
	}
	var c HarborConfig
	if err := json.Unmarshal(r.Config, &c); err != nil || c.URL == "" {
		return HarborConfig{}, false
	}
	return c, true
}

func RedactedConfig(kind string, raw json.RawMessage) json.RawMessage {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}

	for _, k := range []string{"token", "password", "webhook_url"} {
		if v, ok := m[k].(string); ok && v != "" {
			m[k] = "***"
		}
	}
	out, _ := json.Marshal(m)
	return out
}
