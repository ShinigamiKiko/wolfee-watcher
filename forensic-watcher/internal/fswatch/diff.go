package fswatch

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	OpAdded    = "added"
	OpModified = "modified"
	OpDeleted  = "deleted"
	OpReplaced = "replaced"
	OpRestored = "restored"
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
			w.pollWatch(ctx, s)
		}(s)
	}
	wg.Wait()
}

func (w *Watcher) pollWatch(ctx context.Context, s *watchState) {
	key := s.ns + "/" + s.pod
	l, err := w.resolveLayer(ctx, s.ns, s.pod, true)
	switch {
	case err == nil && l.containerID == s.containerID:
		if err := w.diffAndStore(ctx, s); err != nil {
			log.Printf("[fswatch] diff %s: %v — baseline kept, retrying next poll", key, err)
		}
	case err == nil:
		w.finalDiff(ctx, s)
		next, err := w.newWatchState(s.ns, s.pod, l)
		if err != nil {
			log.Printf("[fswatch] %s restarted as %s but its layer is unreadable: %v", key, short(l.containerID), err)
			return
		}
		w.mu.Lock()
		if w.watches[key] == s {
			w.watches[key] = next
		}
		w.mu.Unlock()
		log.Printf("[fswatch] %s container restarted %s -> %s, new baseline=%d files", key, short(s.containerID), short(l.containerID), len(next.lastSnap))
		w.flushPending(ctx, next)
	case errors.Is(err, errPodGone), errors.Is(err, errNotRunning):
		w.finalDiff(ctx, s)
		w.retire(ctx, s, err)
	case errors.Is(err, errOtherNode):
		w.mu.Lock()
		if w.watches[key] == s {
			delete(w.watches, key)
		}
		w.mu.Unlock()
		log.Printf("[fswatch] %s moved to another node, dropped locally", key)
	default:
		if err := w.diffAndStore(ctx, s); err != nil {
			log.Printf("[fswatch] diff %s: %v — baseline kept, retrying next poll", key, err)
		}
	}
}

func (w *Watcher) finalDiff(ctx context.Context, s *watchState) {
	if _, err := os.Stat(s.upperDir); err != nil {
		return
	}
	if err := w.diffAndStore(ctx, s); err != nil {
		log.Printf("[fswatch] final diff %s/%s: %v", s.ns, s.pod, err)
	}
}

func (w *Watcher) retire(ctx context.Context, s *watchState, reason error) {
	key := s.ns + "/" + s.pod
	w.mu.Lock()
	if w.watches[key] == s {
		delete(w.watches, key)
	}
	w.mu.Unlock()
	if w.central != nil {
		opCtx, cancel := context.WithTimeout(ctx, pgOpTimeout)
		defer cancel()
		if err := w.central.DeleteWatch(opCtx, s.ns, s.pod); err != nil {
			log.Printf("[fswatch] unregister finished watch %s: %v", key, err)
		}
	}
	log.Printf("[fswatch] stopped watching %s: %v", key, reason)
}

func (w *Watcher) diffAndStore(ctx context.Context, s *watchState) error {
	w.flushPending(ctx, s)
	prev := w.copyLastSnap(s)
	current, err := w.snapDir(s.upperDir, prev)
	if err != nil {
		return err
	}
	diffs := buildDiffs(current, prev, lowerLookup(s.lowerDirs), time.Now().UTC().Format(time.RFC3339))
	if len(diffs) == 0 {
		w.storeLastSnap(s, current)
		return nil
	}
	for i := range diffs {
		diffs[i].ContainerID = s.containerID
	}
	log.Printf("[fswatch] %s/%s diff: %d changes", s.ns, s.pod, len(diffs))
	if err := w.insertDiffs(ctx, s, diffs); err != nil {
		return err
	}
	w.storeLastSnap(s, current)
	return nil
}

func (w *Watcher) flushPending(ctx context.Context, s *watchState) {
	w.mu.RLock()
	pending := s.pending
	w.mu.RUnlock()
	if len(pending) == 0 {
		return
	}
	if err := w.insertDiffs(ctx, s, pending); err != nil {
		log.Printf("[fswatch] baseline %s/%s (%d files) not stored yet: %v", s.ns, s.pod, len(pending), err)
		return
	}
	w.mu.Lock()
	s.pending = nil
	w.mu.Unlock()
}

func lowerLookup(lowers []string) func(string) bool {
	return func(path string) bool {
		for _, lower := range lowers {
			info, err := os.Lstat(filepath.Join(lower, path))
			if err != nil {
				continue
			}
			return !isOverlayWhiteout(info)
		}
		return false
	}
}

func baselineEntries(current map[string]FileEntry, inLower func(string) bool, now, containerID string) []FileEntry {
	out := make([]FileEntry, 0, len(current))
	for path, cur := range current {
		e := cur
		e.SnappedAt = now
		e.ContainerID = containerID
		e.Baseline = true
		switch cur.kind {
		case kindWhiteout:
			e.Op = OpDeleted
		case kindOpaqueDir:
			e.Op = OpReplaced
		default:
			e.Op = OpAdded
			if inLower(path) {
				e.Op = OpModified
			}
		}
		out = append(out, e)
	}
	sortEntries(out)
	return out
}

func buildDiffs(current, prev map[string]FileEntry, inLower func(string) bool, now string) []FileEntry {
	var diffs []FileEntry
	for path, cur := range current {
		p, had := prev[path]
		e := cur
		e.SnappedAt = now
		switch cur.kind {
		case kindWhiteout:
			if had && p.kind == kindWhiteout {
				continue
			}
			e.Op = OpDeleted
			if had && p.kind == kindFile {
				e.Size, e.Mtime = p.Size, p.Mtime
			}
		case kindOpaqueDir:
			if had && p.kind == kindOpaqueDir {
				continue
			}
			e.Op = OpReplaced
		default:
			switch {
			case !had || p.kind != kindFile:
				e.Op = OpAdded
				if inLower(path) {
					e.Op = OpModified
				}
			case p.SHA256 != cur.SHA256 || p.Mtime != cur.Mtime || p.Size != cur.Size:
				e.Op = OpModified
			default:
				continue
			}
		}
		diffs = append(diffs, e)
	}
	for path, p := range prev {
		if _, ok := current[path]; ok {
			continue
		}
		switch p.kind {
		case kindOpaqueDir:
			continue
		case kindWhiteout:
			diffs = append(diffs, FileEntry{Path: path, Op: OpRestored, SnappedAt: now})
		default:
			diffs = append(diffs, FileEntry{Path: path, Op: OpDeleted, Size: p.Size, Mtime: p.Mtime, SnappedAt: now})
		}
	}
	sortEntries(diffs)
	return diffs
}

func sortEntries(entries []FileEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
}

func (w *Watcher) copyLastSnap(s *watchState) map[string]FileEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	prev := make(map[string]FileEntry, len(s.lastSnap))
	for k, v := range s.lastSnap {
		prev[k] = v
	}
	return prev
}

func (w *Watcher) storeLastSnap(s *watchState, current map[string]FileEntry) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s.lastSnap = current
}

func (w *Watcher) insertDiffs(ctx context.Context, s *watchState, diffs []FileEntry) error {
	if w.central == nil {
		return nil
	}
	iCtx, cancel := context.WithTimeout(ctx, pushTimeout)
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
	return baselineEntries(s.lastSnap, lowerLookup(s.lowerDirs), s.startedAt.UTC().Format(time.RFC3339), s.containerID)
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
