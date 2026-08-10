package watchring

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/events"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

const maxPerKey = 500
const retention = 24 * time.Hour

type entry struct {
	raw json.RawMessage
	ts  time.Time
}

type Ring struct {
	mu   sync.RWMutex
	bufs map[string][]entry
}

func New(ctx context.Context) *Ring {
	r := &Ring{bufs: make(map[string][]entry)}
	go func() {
		t := time.NewTicker(retention)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.evict()
			}
		}
	}()
	return r
}

func (r *Ring) evict() {
	cutoff := time.Now().Add(-retention)
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, buf := range r.bufs {
		i := 0
		for i < len(buf) && buf[i].ts.Before(cutoff) {
			i++
		}
		switch {
		case i == len(buf):
			delete(r.bufs, key)
		case i > 0:
			r.bufs[key] = buf[i:]
		}
	}
}

func (r *Ring) Add(ns, pod, podUID string, kind events.Kind, name string, raw json.RawMessage, ts time.Time) {
	key := ringKey(ns, pod, podUID, kind, name)
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-retention)
	buf := r.bufs[key]

	i := 0
	for i < len(buf) && buf[i].ts.Before(cutoff) {
		i++
	}
	buf = buf[i:]
	cp := make(json.RawMessage, len(raw))
	copy(cp, raw)
	buf = append(buf, entry{raw: cp, ts: ts})
	if len(buf) > maxPerKey {
		buf = buf[len(buf)-maxPerKey:]
	}
	r.bufs[key] = buf
}

func (r *Ring) Get(ns, pod, podUID, containerID string, selection store.PodWatchSelection) []json.RawMessage {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cutoff := time.Now().Add(-retention)
	var out []json.RawMessage
	appendEvents := func(kind events.Kind, names []string) {
		for _, name := range names {
			for _, e := range r.bufs[ringKey(ns, pod, podUID, kind, name)] {
				if !e.ts.Before(cutoff) {
					out = append(out, e.raw)
				}
			}
			if podUID != "" && containerID != "" {
				for _, e := range r.bufs[ringKey(ns, pod, "", kind, name)] {
					if e.ts.Before(cutoff) || rawContainerID(e.raw) != containerID {
						continue
					}
					out = append(out, e.raw)
				}
			}
		}
	}
	appendEvents(events.Syscall, selection.Syscalls)
	appendEvents(events.LSMHook, selection.LSMHooks)
	appendEvents(events.Tracepoint, selection.Tracepoints)
	return out
}

func rawContainerID(raw json.RawMessage) string {
	var ev map[string]interface{}
	if json.Unmarshal(raw, &ev) != nil {
		return ""
	}
	if value, ok := ev["containerId"].(string); ok {
		return value
	}
	if value, ok := ev["container_id"].(string); ok {
		return value
	}
	return ""
}

func ringKey(ns, pod, podUID string, kind events.Kind, name string) string {
	return ns + "/" + pod + "/" + podUID + "/" + string(kind) + "/" + name
}
