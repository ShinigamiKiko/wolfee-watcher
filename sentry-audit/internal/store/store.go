package store

import (
	"strconv"
	"sync"
	"time"

	"github.com/wolfee-watcher/sentry-audit/internal/webhook"
)

const (
	ringCap = 1000

	AuditEventTTL = 24 * time.Hour
)

type entry struct {
	id int64
	ts time.Time
	ev webhook.AuditEvent
}

type Store struct {
	mu     sync.RWMutex
	events []entry
	nextID int64
}

func New() *Store {
	return &Store{nextID: 1}
}

func (s *Store) Push(ev webhook.AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, entry{id: s.nextID, ts: time.Now(), ev: ev})
	s.nextID++
	if len(s.events) > ringCap {
		s.events = s.events[len(s.events)-ringCap:]
	}
}

func (s *Store) GetSince(since string) (webhook.EventPage, error) {
	sinceID, _ := strconv.ParseInt(since, 10, 64)
	cutoff := time.Now().Add(-AuditEventTTL)

	s.mu.RLock()
	defer s.mu.RUnlock()
	events := []webhook.AuditEvent{}
	lastID := since
	if lastID == "" {
		lastID = "0"
	}
	for _, e := range s.events {
		if e.id <= sinceID || e.ts.Before(cutoff) {
			continue
		}
		events = append(events, e.ev)
		lastID = strconv.FormatInt(e.id, 10)
		if len(events) >= 200 {
			break
		}
	}
	return webhook.EventPage{Events: events, LastID: lastID}, nil
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}
