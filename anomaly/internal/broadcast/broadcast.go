package broadcast

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	subscriberBuffer = 256
	maxDropsPerSub   = 256
	dropLogEvery     = time.Minute
)

type subscriber struct {
	ch    chan []byte
	drops atomic.Int32
}

type Hub struct {
	mu   sync.RWMutex
	subs map[chan []byte]*subscriber

	dropped  atomic.Int64
	evicted  atomic.Int64
	lastWarn atomic.Int64
}

func New() *Hub {
	return &Hub{subs: make(map[chan []byte]*subscriber)}
}

func (h *Hub) Subscribe() chan []byte {
	ch := make(chan []byte, subscriberBuffer)
	h.mu.Lock()
	h.subs[ch] = &subscriber{ch: ch}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	_, present := h.subs[ch]
	delete(h.subs, ch)
	h.mu.Unlock()
	if present {
		close(ch)
	}
}

func (h *Hub) Broadcast(data []byte) {
	h.mu.RLock()
	slow := make([]chan []byte, 0, 4)
	for ch, sub := range h.subs {
		select {
		case ch <- data:
			sub.drops.Store(0)
		default:
			total := h.dropped.Add(1)
			if sub.drops.Add(1) >= maxDropsPerSub {
				slow = append(slow, ch)
			}
			h.warnDropped(total)
		}
	}
	h.mu.RUnlock()

	for _, ch := range slow {
		h.evicted.Add(1)
		slog.Warn("sse_subscriber_evicted",
			"component", "anomaly-detector/broadcast",
			"reason", "buffer_full",
			"max_drops", maxDropsPerSub,
			"evicted_total", h.evicted.Load())
		h.Unsubscribe(ch)
	}
}

func (h *Hub) warnDropped(total int64) {
	now := time.Now()
	last := h.lastWarn.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < dropLogEvery {
		return
	}
	if !h.lastWarn.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	slog.Warn("sse_event_dropped",
		"component", "anomaly-detector/broadcast",
		"reason", "slow_subscriber",
		"dropped_total", total)
}

func (h *Hub) Stats() (subscribers int, dropped, evicted int64) {
	if h == nil {
		return 0, 0, 0
	}
	h.mu.RLock()
	subscribers = len(h.subs)
	h.mu.RUnlock()
	return subscribers, h.dropped.Load(), h.evicted.Load()
}
