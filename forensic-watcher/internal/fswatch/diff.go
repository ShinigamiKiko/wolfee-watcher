package fswatch

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

func (w *Watcher) GetDiff(ctx context.Context, ns, pod string) ([]FileEntry, error) {
	if w.central == nil {
		return w.getInMemDiff(ns, pod), nil
	}
	opCtx, cancel := context.WithTimeout(ctx, pgOpTimeout)
	defer cancel()
	return w.central.PullDiff(opCtx, ns, pod)
}

func (w *Watcher) pollAll(ctx context.Context) {
	w.mu.RLock()
	states := make([]*watchState, 0, len(w.watches))
	for _, s := range w.watches {
		states = append(states, s)
	}
	w.mu.RUnlock()

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, s := range states {
		wg.Add(1)
		sem <- struct{}{}
		go func(s *watchState) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := w.diffAndStore(ctx, s); err != nil {
				log.Printf("[fswatch] diff %s/%s: %v — baseline kept, retrying next poll", s.ns, s.pod, err)
			}
		}(s)
	}
	wg.Wait()
}

func (w *Watcher) diffAndStore(ctx context.Context, s *watchState) error {
	current, err := w.snapDir(s.upperDir)
	if err != nil {
		return err
	}
	currentMap := mapEntriesByPath(current)
	prevSnap := w.copyLastSnap(s)
	diffs := buildDiffs(currentMap, prevSnap)
	if len(diffs) == 0 {
		w.storeLastSnap(s, currentMap)
		log.Printf("[fswatch] %s/%s no changes (snap=%d files)", s.ns, s.pod, len(currentMap))
		return nil
	}
	log.Printf("[fswatch] %s/%s diff: %d changes", s.ns, s.pod, len(diffs))

	if err := w.insertDiffs(ctx, s, diffs); err != nil {
		return err
	}
	w.storeLastSnap(s, currentMap)
	return nil
}

func mapEntriesByPath(entries []FileEntry) map[string]FileEntry {
	currentMap := make(map[string]FileEntry, len(entries))
	for _, e := range entries {
		currentMap[e.Path] = e
	}
	return currentMap
}

func (w *Watcher) copyLastSnap(s *watchState) map[string]FileEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	prevSnap := make(map[string]FileEntry, len(s.lastSnap))
	for k, v := range s.lastSnap {
		prevSnap[k] = v
	}
	return prevSnap
}

func buildDiffs(currentMap, prevSnap map[string]FileEntry) []FileEntry {
	now := time.Now().UTC().Format(time.RFC3339)
	var diffs []FileEntry
	for path, cur := range currentMap {
		cur.SnappedAt = now
		if prev, ok := prevSnap[path]; !ok {
			cur.Op = "added"
			diffs = append(diffs, cur)
		} else if prev.SHA256 != cur.SHA256 || prev.Mtime != cur.Mtime {
			cur.Op = "modified"
			diffs = append(diffs, cur)
		}
	}
	for path, prev := range prevSnap {
		if _, ok := currentMap[path]; ok {
			continue
		}
		diffs = append(diffs, FileEntry{
			Path:      path,
			Op:        "deleted",
			Size:      prev.Size,
			Mtime:     prev.Mtime,
			SnappedAt: now,
		})
	}
	return diffs
}

func (w *Watcher) storeLastSnap(s *watchState, currentMap map[string]FileEntry) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s.lastSnap = currentMap
}

func (w *Watcher) insertDiffs(ctx context.Context, s *watchState, diffs []FileEntry) error {
	if w.central == nil {
		return nil
	}
	iCtx, cancel := context.WithTimeout(ctx, pgOpTimeout)
	defer cancel()
	if err := w.central.PushEvents(iCtx, s.ns, s.pod, diffs); err != nil {
		return fmt.Errorf("push forensic events: %w", err)
	}
	return nil
}

func (w *Watcher) getInMemDiff(ns, pod string) []FileEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	s, ok := w.watches[ns+"/"+pod]
	if !ok {
		return nil
	}
	entries := make([]FileEntry, 0, len(s.lastSnap))
	for _, e := range s.lastSnap {
		entries = append(entries, e)
	}
	return entries
}

func trimRecentDiff(entries []FileEntry, cutoff time.Time) []FileEntry {
	out := entries[:0]
	for _, e := range entries {
		ts, err := time.Parse(time.RFC3339, e.SnappedAt)
		if err != nil || ts.After(cutoff) {
			out = append(out, e)
		}
	}
	return out
}

func validateTTL(entries []FileEntry) []FileEntry {
	return trimRecentDiff(entries, time.Now().Add(-fsTTL))
}
