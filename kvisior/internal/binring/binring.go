package binring

import (
	"encoding/json"
	"sync"
	"time"
)

const (
	retention = 24 * time.Hour

	maxEvents = 20_000
)

type entry struct {
	ts  time.Time
	raw json.RawMessage
}

type Ring struct {
	mu  sync.Mutex
	buf []entry
}

func New() *Ring { return &Ring{} }

func (r *Ring) Add(raw json.RawMessage, ts time.Time) {
	cp := make(json.RawMessage, len(raw))
	copy(cp, raw)

	r.mu.Lock()
	defer r.mu.Unlock()

	r.buf = append(r.buf, entry{ts: ts, raw: cp})
	r.prune()
}

func (r *Ring) prune() {
	cutoff := time.Now().Add(-retention)
	i := 0
	for i < len(r.buf) && r.buf[i].ts.Before(cutoff) {
		i++
	}
	if i > 0 {
		r.buf = r.buf[i:]
	}
	if len(r.buf) > maxEvents {
		r.buf = r.buf[len(r.buf)-maxEvents:]
	}
}

func (r *Ring) Snapshot() []json.RawMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	out := make([]json.RawMessage, len(r.buf))
	for i, e := range r.buf {
		out[i] = e.raw
	}
	return out
}

func (r *Ring) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buf)
}
