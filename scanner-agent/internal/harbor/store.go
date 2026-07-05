package harbor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	URL      string `json:"url"`
	Username string `json:"username,omitempty"`
	Token    string `json:"token"`
}

type Store struct {
	pullURL string
	secret  string
	hc      *http.Client

	mu  sync.RWMutex
	cfg *Config
}

func New(ctx context.Context) *Store {
	base := strings.TrimRight(os.Getenv("KVISIOR_URL"), "/")
	if base == "" {
		return nil
	}
	s := &Store{
		pullURL: base + "/internal/pull/integration?kind=harbor",
		secret:  os.Getenv("INTERNAL_PUSH_SECRET"),
		hc:      &http.Client{Timeout: 5 * time.Second},
	}
	s.refresh(ctx)
	return s
}

func (s *Store) Config() *Config {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg == nil {
		return nil
	}
	cp := *s.cfg
	return &cp
}

func (s *Store) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.refresh(ctx)
			}
		}
	}()
}

func (s *Store) refresh(ctx context.Context) {
	rCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	raw, err := s.pull(rCtx)
	if err != nil {

		log.Printf("[harbor] integration pull failed: %v — keeping previous credentials", err)
		return
	}
	if raw == nil {

		s.clear("integration absent or disabled")
		return
	}

	var c Config
	if err := json.Unmarshal(raw, &c); err != nil || c.URL == "" || c.Token == "" {
		s.clear("invalid integration config")
		return
	}

	s.mu.Lock()
	changed := s.cfg == nil || *s.cfg != c
	s.cfg = &c
	s.mu.Unlock()
	if changed {
		log.Printf("[harbor] credentials refreshed (url=%s)", c.URL)
	}
}

func (s *Store) clear(reason string) {
	s.mu.Lock()
	had := s.cfg != nil
	s.cfg = nil
	s.mu.Unlock()
	if had {
		log.Printf("[harbor] %s — credentials cleared", reason)
	}
}

func (s *Store) pull(ctx context.Context) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.pullURL, nil)
	if err != nil {
		return nil, err
	}
	if s.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", s.secret)
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("kvisior responded %d", resp.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}
