package fswatch

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
)

const (
	fsTTL        = 24 * time.Hour
	pollInterval = 2 * time.Minute
	pgOpTimeout  = 5 * time.Second

	maxFilesPerDiff = 10_000
)

type FileEntry struct {
	Path      string `json:"path"`
	Op        string `json:"op"`
	Size      int64  `json:"size"`
	Mtime     string `json:"mtime"`
	SHA256    string `json:"sha256,omitempty"`
	SnappedAt string `json:"snapped_at"`
}

type Watcher struct {
	nodeName       string
	containerdRoot string
	central        *CentralClient
	client         kubernetes.Interface

	mu      sync.RWMutex
	watches map[string]*watchState
}

type watchState struct {
	ns        string
	pod       string
	upperDir  string
	startedAt time.Time
	lastSnap  map[string]FileEntry
}

func New(nodeName, containerdRoot string, central *CentralClient, client kubernetes.Interface) *Watcher {
	return &Watcher{
		nodeName:       nodeName,
		containerdRoot: containerdRoot,
		central:        central,
		client:         client,
		watches:        make(map[string]*watchState),
	}
}

func (w *Watcher) Run(ctx context.Context) {
	log.Printf("[fswatch] started on node=%s poll=%s", w.nodeName, pollInterval)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Printf("[fswatch] poll tick — checking %d watches", len(w.watches))
			w.pollAll(ctx)
		}
	}
}

func (w *Watcher) StartWatch(ctx context.Context, ns, pod string) error {
	key := ns + "/" + pod

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.watches[key]; ok {
		return nil
	}

	upperDir, err := w.findUpperDir(ctx, ns, pod)
	if err != nil {
		return fmt.Errorf("find upperdir for %s: %w", key, err)
	}
	state, entries, err := w.newWatchState(upperDir, ns, pod)
	if err != nil {
		return err
	}
	w.watches[key] = state
	w.persistWatch(ctx, key, ns, pod)
	log.Printf("[fswatch] watching %s (upperDir=%s, baseline=%d files)", key, upperDir, len(entries))
	return nil
}

func (w *Watcher) newWatchState(upperDir, ns, pod string) (*watchState, []FileEntry, error) {
	state := &watchState{
		ns:        ns,
		pod:       pod,
		upperDir:  upperDir,
		startedAt: time.Now(),
		lastSnap:  make(map[string]FileEntry),
	}
	entries, err := w.snapDir(upperDir)
	if err != nil {
		return nil, nil, fmt.Errorf("initial snap: %w", err)
	}
	for _, e := range entries {
		state.lastSnap[e.Path] = e
	}
	return state, entries, nil
}

func (w *Watcher) persistWatch(ctx context.Context, key, ns, pod string) {
	if w.central == nil {
		return
	}
	opCtx, cancel := context.WithTimeout(ctx, pgOpTimeout)
	defer cancel()
	if err := w.central.UpsertWatch(opCtx, ns, pod); err != nil {
		log.Printf("[fswatch] register watch %s with kvisior: %v", key, err)
	}
}

func (w *Watcher) StopWatch(ctx context.Context, ns, pod string) {
	key := ns + "/" + pod
	w.mu.Lock()
	delete(w.watches, key)
	w.mu.Unlock()
	if w.central != nil {
		opCtx, cancel := context.WithTimeout(ctx, pgOpTimeout)
		defer cancel()
		if err := w.central.DeleteWatch(opCtx, ns, pod); err != nil {
			log.Printf("[fswatch] unregister watch %s with kvisior: %v", key, err)
		}
	}
	log.Printf("[fswatch] stopped watching %s", key)
}

func (w *Watcher) IsWatching(ns, pod string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.watches[ns+"/"+pod]
	return ok
}

func (w *Watcher) ActiveWatches() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]string, 0, len(w.watches))
	for k := range w.watches {
		out = append(out, k)
	}
	return out
}

func (w *Watcher) FindUpperDir(ctx context.Context, ns, pod string) (string, error) {
	return w.findUpperDir(ctx, ns, pod)
}

func (w *Watcher) GetUpperDir(ns, pod string) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	s, ok := w.watches[ns+"/"+pod]
	if !ok {
		return "", fmt.Errorf("not watching %s/%s", ns, pod)
	}
	return s.upperDir, nil
}
