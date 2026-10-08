package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
)

const kafkaProduceErrorLogEvery = time.Minute

var lastKafkaProduceErrorLog atomic.Int64

func (h *Hub) Broadcast(ev *mapper.UIEvent) {
	h.cntReceived.Add(1)
	if !h.wanted(ev) {
		h.cntDropped.Add(1)
		h.cntFiltered.Add(1)
		return
	}
	if h.shouldDedup(ev) && h.markSeen(dedupKey(ev)) {
		h.cntDedup.Add(1)
		return
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

	h.producer.TryProduce(context.Background(), &kgo.Record{Value: data, Key: []byte(ev.Namespace + "/" + ev.Pod)}, func(_ *kgo.Record, err error) {
		if err != nil {
			dropped := h.cntDropped.Add(1)
			if shouldLogKafkaProduceError() {
				slog.Warn("kafka_produce_failed",
					"component", "tracee-bridge/hub",
					"topic", h.kafkaTopic,
					"error", err,
					"shutting_down", h.ctx.Err() != nil,
					"dropped_total", dropped)
			}
		}
	})
}

func (h *Hub) wanted(ev *mapper.UIEvent) bool {
	if alwaysPass[ev.Syscall] || isLSMHook(ev.Syscall) {
		return true
	}
	if ev.Execpath != "" || ev.Cmdline != "" {
		return true
	}
	return h.alerter.WantsSyscall(ev.Syscall)
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

func (h *Hub) shouldDedup(ev *mapper.UIEvent) bool {
	return h.dedupTTL > 0 && ev.Pod != "" && !neverDedup[ev.Syscall]
}

func (h *Hub) markSeen(key string) bool {
	now := time.Now()
	h.dedupMu.Lock()
	defer h.dedupMu.Unlock()
	if last, ok := h.dedup[key]; ok && now.Sub(last) < h.dedupTTL {
		return true
	}
	h.dedup[key] = now
	if len(h.dedup) > h.dedupMaxEntries {
		h.sweepDedupLocked(now)
	}
	return false
}

func (h *Hub) sweepDedupLocked(now time.Time) {
	for k, ts := range h.dedup {
		if now.Sub(ts) >= h.dedupTTL {
			delete(h.dedup, k)
		}
	}
	if len(h.dedup) > h.dedupMaxEntries {
		flushed := h.cntDedupFlush.Add(1)
		slog.Warn("dedup_table_flushed",
			"component", "tracee-bridge/hub",
			"entries", len(h.dedup),
			"max_entries", h.dedupMaxEntries,
			"flush_count", flushed,
			"impact", "next_repeat_of_each_event_passes_through")
		h.dedup = make(map[string]time.Time, h.dedupMaxEntries)
	}
}

func (h *Hub) dedupSweepLoop() {
	t := time.NewTicker(h.dedupTTL)
	defer t.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			h.dedupMu.Lock()
			for k, ts := range h.dedup {
				if now.Sub(ts) >= h.dedupTTL {
					delete(h.dedup, k)
				}
			}
			h.dedupMu.Unlock()
		}
	}
}

func dedupKey(ev *mapper.UIEvent) string {
	var b strings.Builder
	b.Grow(len(ev.Pod) + len(ev.Container) + len(ev.Syscall) + len(ev.Process) + len(ev.Cmdline) + 24)
	b.WriteString(ev.Pod)
	b.WriteByte('|')
	b.WriteString(ev.Container)
	b.WriteByte('|')
	b.WriteString(ev.Syscall)
	b.WriteByte('|')
	b.WriteString(ev.Process)
	b.WriteByte('|')
	switch {
	case ev.Cmdline != "":
		b.WriteString(ev.Cmdline)
	case ev.Execpath != "":
		b.WriteString(ev.Execpath)
	}
	if fp := argsFingerprint(ev.Args); fp != 0 {
		b.WriteByte('|')
		b.WriteString(strconv.FormatUint(fp, 16))
	}
	return b.String()
}

func argsFingerprint(args map[string]interface{}) uint64 {
	if len(args) == 0 {
		return 0
	}
	h := fnv.New64a()
	fmt.Fprintf(h, "%v", args)
	return h.Sum64()
}
