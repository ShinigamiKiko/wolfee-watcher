package podwatch

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/events"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/kvisior/internal/watchring"
)

type watchEntry struct {
	selection store.PodWatchSelection
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
		m.watches[k] = watchEntry{selection: e.PodWatchSelection, updatedAt: e.UpdatedAt}
	}
	m.mu.Unlock()
	return nil
}

type WatchSnapshot struct {
	store.PodWatchSelection
	Since time.Time
}

func (m *Manager) Watches() map[string]WatchSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]WatchSnapshot, len(m.watches))
	for k, e := range m.watches {
		out[k] = WatchSnapshot{PodWatchSelection: cloneSelection(e.selection), Since: e.updatedAt}
	}
	return out
}

func (m *Manager) ShouldCapture(ns, pod string, kind events.Kind, name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := ns + "/" + pod
	selection := m.watches[key].selection
	var names []string
	switch kind {
	case events.LSMHook:
		names = selection.LSMHooks
	case events.Tracepoint:
		names = selection.Tracepoints
	default:
		names = selection.Syscalls
	}
	for _, selected := range names {
		if selected == name {
			return true
		}
	}
	return false
}

func (m *Manager) Add(ns, pod, podUID string, kind events.Kind, name string, raw json.RawMessage, ts time.Time) {
	m.ring.Add(ns, pod, podUID, kind, name, raw, ts)
}

func (m *Manager) GetEvents(ns, pod, podUID, containerID string) []json.RawMessage {
	m.mu.RLock()
	key := ns + "/" + pod
	e := m.watches[key]
	m.mu.RUnlock()
	if len(e.selection.Syscalls)+len(e.selection.LSMHooks)+len(e.selection.Tracepoints) == 0 {
		return nil
	}
	return m.ring.Get(ns, pod, podUID, containerID, e.selection)
}

func (m *Manager) GetWatch(ctx context.Context, ns, pod string) (store.PodWatchSelection, error) {
	if m.store == nil {
		return store.PodWatchSelection{}, nil
	}
	return m.store.GetPodWatch(ctx, ns, pod)
}

func (m *Manager) SetWatch(ctx context.Context, ns, pod string, selection store.PodWatchSelection) error {
	if m.store == nil {
		return nil
	}
	if err := m.store.SetPodWatch(ctx, ns, pod, selection); err != nil {
		return err
	}
	key := ns + "/" + pod
	m.mu.Lock()
	m.watches[key] = watchEntry{selection: cloneSelection(selection), updatedAt: time.Now()}
	m.mu.Unlock()
	return nil
}

func cloneSelection(in store.PodWatchSelection) store.PodWatchSelection {
	return store.PodWatchSelection{
		Syscalls:    append([]string(nil), in.Syscalls...),
		LSMHooks:    append([]string(nil), in.LSMHooks...),
		Tracepoints: append([]string(nil), in.Tracepoints...),
	}
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
