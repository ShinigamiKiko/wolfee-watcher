package push

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"
)

const (
	clientRetryAfter = 75 * time.Second
	clientRetryTries = 3
	clientQueueCap   = 2048
	clientQueueTick  = 15 * time.Second
)

type pendingClient struct {
	cluster, ns, honeypot, id, ip string
	at                            time.Time
	next                          time.Time
	tries                         int
}

type clientQueue struct {
	mu    sync.Mutex
	items []pendingClient
}

func newClientQueue() *clientQueue { return &clientQueue{} }

func (q *clientQueue) add(p pendingClient) {
	p.next = p.at.Add(clientRetryAfter)
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= clientQueueCap {
		q.items = q.items[1:]
	}
	q.items = append(q.items, p)
}

func (q *clientQueue) due(now time.Time) []pendingClient {
	q.mu.Lock()
	defer q.mu.Unlock()
	var due, keep []pendingClient
	for _, p := range q.items {
		if now.Before(p.next) {
			keep = append(keep, p)
		} else {
			due = append(due, p)
		}
	}
	q.items = keep
	return due
}

func (h *Handler) resolveLater(ctx context.Context) {
	t := time.NewTicker(clientQueueTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		for _, p := range h.pending.due(now) {
			c := h.resolveClient(p.cluster, p.ip, p.at)
			if c == nil {
				p.tries++
				if p.tries < clientRetryTries {
					p.next = now.Add(clientRetryAfter)
					h.pending.mu.Lock()
					h.pending.items = append(h.pending.items, p)
					h.pending.mu.Unlock()
				}
				continue
			}
			raw, err := json.Marshal(c)
			if err != nil {
				continue
			}
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			ok, err := h.store.Cluster(p.cluster).AttachHoneypotClient(wctx, p.ns, p.honeypot, p.id, raw)
			cancel()
			if err != nil {
				slog.Warn("honeypot_client_attach_failed", "component", "kvisior/push", "honeypot", p.ns+"/"+p.honeypot, "error", err)
				continue
			}
			if ok {
				slog.Info("honeypot_client_resolved_late", "component", "kvisior/push",
					"honeypot", p.ns+"/"+p.honeypot, "src_ip", p.ip, "pod", c.Namespace+"/"+c.Pod)
			}
		}
	}
}
