package store

import (
	"sync"
	"time"
)

const RetentionTTL = 24 * time.Hour

type RunStatus string

const (
	StatusIdle    RunStatus = "idle"
	StatusRunning RunStatus = "running"
	StatusDone    RunStatus = "done"
	StatusError   RunStatus = "error"
)

type ToolResult struct {
	Status    RunStatus   `json:"status"`
	StartedAt time.Time   `json:"started_at,omitempty"`
	DoneAt    time.Time   `json:"done_at,omitempty"`
	Parsed    interface{} `json:"parsed"`
	Error     string      `json:"error,omitempty"`
}

type AuditRun struct {
	Bench  ToolResult `json:"bench"`
	Hunter ToolResult `json:"hunter"`
}

type Store struct {
	mu     sync.RWMutex
	bench  ToolResult
	hunter ToolResult
}

func New() *Store {
	return &Store{
		bench:  ToolResult{Status: StatusIdle},
		hunter: ToolResult{Status: StatusIdle},
	}
}

func (s *Store) Begin(_ string, doBench, doHunter bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if doBench {
		s.bench = ToolResult{Status: StatusRunning, StartedAt: time.Now()}
	}
	if doHunter {
		s.hunter = ToolResult{Status: StatusRunning, StartedAt: time.Now()}
	}
}

func (s *Store) UpdateBench(_ string, r ToolResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bench = r
}

func (s *Store) UpdateHunter(_ string, r ToolResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hunter = r
}

func (s *Store) Finish(_ string) {}

func (s *Store) Current() *AuditRun {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &AuditRun{Bench: s.bench, Hunter: s.hunter}
}

func (s *Store) History() []*AuditRun {
	return []*AuditRun{s.Current()}
}
