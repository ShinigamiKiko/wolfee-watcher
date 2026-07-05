package hub

import (
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
)

const kafkaProduceErrorLogEvery = time.Minute

var lastKafkaProduceErrorLog atomic.Int64

func (h *Hub) Broadcast(ev *mapper.UIEvent) {
	h.cntReceived.Add(1)
	if !alwaysPass[ev.Syscall] && !isLSMHook(ev.Syscall) && ev.Execpath == "" && ev.Cmdline == "" {
		h.cntDropped.Add(1)
		return
	}
	if ev.Pod != "" {
		key := dedupKey(ev)
		h.dedupMu.Lock()
		now := time.Now()
		if now.Sub(h.dedup[key]) < dedupTTL {
			h.dedupMu.Unlock()
			h.cntDedup.Add(1)
			return
		}
		h.dedup[key] = now
		if len(h.dedup) > 5000 {
			h.dedup = make(map[string]time.Time)
		}
		h.dedupMu.Unlock()
	}
	h.cntPassed.Add(1)
	data, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("event_marshal_failed",
			"component", "tracee-bridge/hub",
			"error", err,
			"namespace", ev.Namespace,
			"pod", ev.Pod)
		return
	}

	h.producer.Produce(h.ctx, &kgo.Record{Value: data, Key: []byte(ev.Namespace + "/" + ev.Pod)}, func(_ *kgo.Record, err error) {
		if err != nil && h.ctx.Err() == nil {
			dropped := h.cntDropped.Add(1)
			if shouldLogKafkaProduceError() {
				slog.Warn("kafka_produce_failed",
					"component", "tracee-bridge/hub",
					"topic", h.kafkaTopic,
					"error", err,
					"dropped_total", dropped)
			}
		}
	})
}

func shouldLogKafkaProduceError() bool {
	now := time.Now()
	last := lastKafkaProduceErrorLog.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < kafkaProduceErrorLogEvery {
		return false
	}
	return lastKafkaProduceErrorLog.CompareAndSwap(last, now.UnixNano())
}

func (h *Hub) sendToClient(c *client, data []byte) {
	if c.closed.Load() {
		return
	}
	select {
	case c.ch <- data:
		c.drops.Store(0)
	default:
		h.cntSSEDrops.Add(1)
		if c.drops.Add(1) >= h.maxClientDrops {
			h.mu.Lock()
			delete(h.clients, c)
			h.mu.Unlock()
			c.close()
			h.cntSSEEvict.Add(1)
		}
	}
}

func dedupKey(ev *mapper.UIEvent) string {
	switch {
	case ev.Cmdline != "":
		return ev.Pod + ":" + ev.Syscall + ":" + ev.Process + ":" + ev.Cmdline
	case ev.Execpath != "":
		return ev.Pod + ":" + ev.Syscall + ":" + ev.Process + ":" + ev.Execpath
	case ev.Process != "":
		return ev.Pod + ":" + ev.Syscall + ":" + ev.Process
	case ev.Syscall != "":
		return ev.Pod + ":" + ev.Syscall
	default:
		return ev.Pod
	}
}
