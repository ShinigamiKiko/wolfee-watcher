package podwatch

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/kvisior/internal/watchring"
)

type watchEntry struct {
	syscalls  []string
	updatedAt time.Time
}

type Manager struct {
	mu      sync.RWMutex
	watches map[string]watchEntry
	ring    *watchring.Ring
	store   *store.Store
}

func New(st *store.Store, ring *watchring.Ring) *Manager {
	return &Manager{
		watches: make(map[string]watchEntry),
		ring:    ring,
		store:   st,
	}
}

func (m *Manager) Load(ctx context.Context) error {
	if m.store == nil {
		return nil
	}
	rows, err := m.store.ListPodWatches(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.watches = make(map[string]watchEntry, len(rows))
	for k, e := range rows {
		m.watches[k] = watchEntry{syscalls: e.Syscalls, updatedAt: e.UpdatedAt}
	}
	m.mu.Unlock()
	return nil
}

type WatchSnapshot struct {
	Syscalls []string
	Since    time.Time
}

func (m *Manager) Watches() map[string]WatchSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]WatchSnapshot, len(m.watches))
	for k, e := range m.watches {
		cp := make([]string, len(e.syscalls))
		copy(cp, e.syscalls)
		out[k] = WatchSnapshot{Syscalls: cp, Since: e.updatedAt}
	}
	return out
}

func (m *Manager) ShouldCapture(ns, pod, syscall string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := ns + "/" + pod
	for _, sc := range m.watches[key].syscalls {
		if sc == syscall {
			return true
		}
	}
	return false
}

func (m *Manager) Add(ns, pod, syscall string, raw json.RawMessage, ts time.Time) {
	m.ring.Add(ns, pod, syscall, raw, ts)
}

func (m *Manager) GetEvents(ns, pod string) []json.RawMessage {
	m.mu.RLock()
	key := ns + "/" + pod
	e := m.watches[key]
	m.mu.RUnlock()
	if len(e.syscalls) == 0 {
		return nil
	}
	return m.ring.Get(ns, pod, e.syscalls)
}

func (m *Manager) GetWatch(ctx context.Context, ns, pod string) ([]string, error) {
	if m.store == nil {
		return nil, nil
	}
	return m.store.GetPodWatch(ctx, ns, pod)
}

func (m *Manager) SetWatch(ctx context.Context, ns, pod string, syscalls []string) error {
	if m.store == nil {
		return nil
	}
	if err := m.store.SetPodWatch(ctx, ns, pod, syscalls); err != nil {
		return err
	}
	key := ns + "/" + pod
	m.mu.Lock()
	m.watches[key] = watchEntry{syscalls: syscalls, updatedAt: time.Now()}
	m.mu.Unlock()
	return nil
}

func (m *Manager) DeleteWatch(ctx context.Context, ns, pod string) error {
	if m.store == nil {
		return nil
	}
	if err := m.store.DeletePodWatch(ctx, ns, pod); err != nil {
		return err
	}
	key := ns + "/" + pod
	m.mu.Lock()
	delete(m.watches, key)
	m.mu.Unlock()
	return nil
}
