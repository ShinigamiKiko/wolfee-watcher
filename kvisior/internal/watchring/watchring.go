package watchring

import (
	"context"
	"encoding/json"
	"sync"
	"time"
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

func (r *Ring) Add(ns, pod, syscall string, raw json.RawMessage, ts time.Time) {
	key := ns + "/" + pod + "/" + syscall
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

func (r *Ring) Get(ns, pod string, syscalls []string) []json.RawMessage {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cutoff := time.Now().Add(-retention)
	var out []json.RawMessage
	for _, sc := range syscalls {
		key := ns + "/" + pod + "/" + sc
		for _, e := range r.bufs[key] {
			if !e.ts.Before(cutoff) {
				out = append(out, e.raw)
			}
		}
	}
	return out
}
