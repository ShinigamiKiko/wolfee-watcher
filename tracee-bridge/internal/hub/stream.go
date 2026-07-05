package hub

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
)

func (h *Hub) sseFanOutLoop() {
	for {
		if h.ctx.Err() != nil {
			return
		}
		fetches := h.sseConsumer.PollFetches(h.ctx)
		if errs := fetches.Errors(); len(errs) > 0 {
			for _, e := range errs {
				if h.ctx.Err() == nil {
					log.Printf("[hub] sse consumer error: topic=%s partition=%d: %v", e.Topic, e.Partition, e.Err)
				}
			}
			continue
		}
		fetches.EachRecord(func(r *kgo.Record) {
			data := r.Value

			h.mu.Lock()
			h.memHistory = append(h.memHistory, data)
			if int64(len(h.memHistory)) > streamMaxMem {
				trimmed := make([][]byte, streamMaxMem)
				copy(trimmed, h.memHistory[len(h.memHistory)-int(streamMaxMem):])
				h.memHistory = trimmed
			}
			h.mu.Unlock()

			if h.alerter != nil && h.alerter.RuleCount() > 0 {
				var ev mapper.UIEvent
				if err := json.Unmarshal(data, &ev); err == nil {
					h.alerter.Evaluate(&ev)
				}
			}

			h.mu.RLock()
			clients := make([]*client, 0, len(h.clients))
			for c := range h.clients {
				clients = append(clients, c)
			}
			h.mu.RUnlock()
			for _, c := range clients {
				h.sendToClient(c, data)
			}
		})
	}
}

func (h *Hub) ServeSSE(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no")

	c := newClient(chanBuf)
	hist := h.getHistory()
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
		c.close()
	}()

	if h.debugLogs {
		log.Printf("[sse] connected remote=%s history=%d pg=%v", r.RemoteAddr, len(hist), h.pool != nil)
	}
	write := func(data []byte) bool {
		buf := make([]byte, 0, len(data)+8)
		buf = append(buf, "data: "...)
		buf = append(buf, data...)
		buf = append(buf, '\n', '\n')
		_, err := w.Write(buf)
		return err == nil
	}
	for _, data := range hist {
		if !write(data) {
			return
		}
	}
	fl.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-c.done:
			return
		case <-heartbeat.C:
			if _, err := w.Write([]byte(": heartbeat\n\n")); err != nil {
				return
			}
			fl.Flush()
		case data := <-c.ch:
			if !write(data) {
				return
			}
			fl.Flush()
		}
	}
}

func (h *Hub) GetEventsSince(_ string) ([]StreamEvent, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]StreamEvent, len(h.memHistory))
	for i, d := range h.memHistory {
		out[i] = StreamEvent{Data: d}
	}
	return out, nil
}

func (h *Hub) GetWindowHistory(hours int, limit int64) ([][]byte, bool, error) {
	if hours <= 0 {
		hours = 6
	}
	if hours > 24 {
		hours = 24
	}
	if limit <= 0 {
		limit = historyReplayCap
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	h.mu.RLock()
	defer h.mu.RUnlock()
	type eventTs struct {
		Ts time.Time `json:"ts"`
	}
	var out [][]byte
	for _, raw := range h.memHistory {
		var e eventTs
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		if !e.Ts.IsZero() && e.Ts.Before(cutoff) {
			continue
		}
		out = append(out, raw)
	}
	if int64(len(out)) > limit {
		out = out[len(out)-int(limit):]
		return out, true, nil
	}
	return out, false, nil
}

func (h *Hub) getHistory() [][]byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	hist := make([][]byte, len(h.memHistory))
	copy(hist, h.memHistory)
	return hist
}
