package fswatch

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
)

const (
	pollInterval = 2 * time.Minute
	pgOpTimeout  = 5 * time.Second
	pushTimeout  = 15 * time.Second

	maxFilesPerDiff = 10_000
)

var (
	ErrPodGone    = errPodGone
	ErrNotRunning = errNotRunning
	ErrOtherNode  = errOtherNode
)

type FileEntry struct {
	Path        string `json:"path"`
	Op          string `json:"op"`
	Size        int64  `json:"size"`
	Mtime       string `json:"mtime"`
	SHA256      string `json:"sha256,omitempty"`
	SnappedAt   string `json:"snapped_at"`
	ContainerID string `json:"container_id,omitempty"`
	Baseline    bool   `json:"baseline,omitempty"`

	kind int
}

type Watcher struct {
	nodeName       string
	containerdRoot string
	central        *CentralClient
	client         kubernetes.Interface

	mu       sync.RWMutex
	watches  map[string]*watchState
	starting map[string]bool
}

type watchState struct {
	ns          string
	pod         string
	containerID string
	upperDir    string
	lowerDirs   []string
	startedAt   time.Time
	lastSnap    map[string]FileEntry
	pending     []FileEntry
}

func New(nodeName, containerdRoot string, central *CentralClient, client kubernetes.Interface) *Watcher {
	return &Watcher{
		nodeName:       nodeName,
		containerdRoot: containerdRoot,
		central:        central,
		client:         client,
		watches:        make(map[string]*watchState),
		starting:       make(map[string]bool),
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
			w.pollAll(ctx)
		}
	}
}

func (w *Watcher) RestoreWatches(ctx context.Context) {
	if w.central == nil {
		return
	}
	opCtx, cancel := context.WithTimeout(ctx, pgOpTimeout)
	watches, err := w.central.PullActiveWatches(opCtx)
	cancel()
	if err != nil {
		log.Printf("[fswatch] restore watches failed: %v", err)
		return
	}
	for _, watch := range watches {
		err := w.StartWatch(ctx, watch.Namespace, watch.Pod, watch.Source)
		switch {
		case err == nil, errors.Is(err, errOtherNode):
		case errors.Is(err, errPodGone), errors.Is(err, errNotRunning):
			opCtx, cancel := context.WithTimeout(ctx, pgOpTimeout)
			if derr := w.central.DeleteWatch(opCtx, watch.Namespace, watch.Pod); derr != nil {
				log.Printf("[fswatch] unregister finished watch %s/%s: %v", watch.Namespace, watch.Pod, derr)
			} else {
				log.Printf("[fswatch] restore %s/%s: %v — watch closed", watch.Namespace, watch.Pod, err)
			}
			cancel()
		default:
			log.Printf("[fswatch] restore %s/%s skipped: %v", watch.Namespace, watch.Pod, err)
		}
	}
}

func (w *Watcher) StartWatch(ctx context.Context, ns, pod, source string) error {
	key := ns + "/" + pod

	w.mu.Lock()
	if _, ok := w.watches[key]; ok || w.starting[key] {
		w.mu.Unlock()
		return nil
	}
	w.starting[key] = true
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		delete(w.starting, key)
		w.mu.Unlock()
	}()

	l, err := w.resolveLayer(ctx, ns, pod, true)
	if err != nil {
		return err
	}
	state, err := w.newWatchState(ns, pod, l)
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.watches[key] = state
	w.mu.Unlock()

	w.persistWatch(ctx, key, ns, pod, source)
	w.flushPending(ctx, state)
	log.Printf("[fswatch] watching %s container=%s (upperDir=%s, baseline=%d files)", key, short(l.containerID), l.upperDir, len(state.lastSnap))
	return nil
}

func (w *Watcher) newWatchState(ns, pod string, l layer) (*watchState, error) {
	snap, err := w.snapDir(l.upperDir, nil)
	if err != nil {
		return nil, fmt.Errorf("initial snap: %w", err)
	}
	now := time.Now()
	return &watchState{
		ns:          ns,
		pod:         pod,
		containerID: l.containerID,
		upperDir:    l.upperDir,
		lowerDirs:   l.lowerDirs,
		startedAt:   now,
		lastSnap:    snap,
		pending:     baselineEntries(snap, lowerLookup(l.lowerDirs), now.UTC().Format(time.RFC3339), l.containerID),
	}, nil
}

func (w *Watcher) persistWatch(ctx context.Context, key, ns, pod, source string) {
	if w.central == nil {
		return
	}
	opCtx, cancel := context.WithTimeout(ctx, pgOpTimeout)
	defer cancel()
	if err := w.central.UpsertWatch(opCtx, ns, pod, source); err != nil {
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
