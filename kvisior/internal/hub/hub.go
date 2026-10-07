package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Type    string          `json:"type"`
	Cluster string          `json:"cluster,omitempty"`
	Data    json.RawMessage `json:"data"`
}

type Publisher interface {
	Publish(Event)
}

type Hub struct {
	mu       sync.Mutex
	clients  map[chan<- Event]struct{}
	buf      []Event
	bufBytes int
	bufMax   int
	latest   map[string]Event
}

const (
	maxClients  = 512
	maxBufBytes = 32 << 20
)

var latestOnly = map[string]bool{
	"sensor_snapshot": true,
}

func New(bufMax int) *Hub {
	return &Hub{
		clients: make(map[chan<- Event]struct{}),
		bufMax:  bufMax,
		latest:  make(map[string]Event),
	}
}

func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if latestOnly[e.Type] {
		h.latest[e.Type+"/"+e.Cluster] = e
	} else {
		h.buf = append(h.buf, e)
		h.bufBytes += len(e.Data)
		for len(h.buf) > 0 && (len(h.buf) > h.bufMax || h.bufBytes > maxBufBytes) {
			h.bufBytes -= len(h.buf[0].Data)
			h.buf[0] = Event{}
			h.buf = h.buf[1:]
		}
	}
	for ch := range h.clients {
		select {
		case ch <- e:
		default:
		}
	}
}

func (h *Hub) Latest(typ string) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Event
	for _, e := range h.latest {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func (h *Hub) Subscribe(ctx context.Context) <-chan Event {
	live := make(chan Event, 256)
	h.mu.Lock()
	if len(h.clients) >= maxClients {
		h.mu.Unlock()
		log.Printf("[hub] SSE client rejected: hub at capacity (%d clients)", maxClients)
		closed := make(chan Event)
		close(closed)
		return closed
	}
	snap := make([]Event, 0, len(h.latest)+len(h.buf))
	for _, e := range h.latest {
		snap = append(snap, e)
	}
	snap = append(snap, h.buf...)
	h.clients[live] = struct{}{}
	nClients := len(h.clients)
	h.mu.Unlock()
	log.Printf("[hub] SSE client connected: clients=%d replaying %d buffered events (%s)", nClients, len(snap), summarizeBuffer(snap))

	out := make(chan Event, 256)
	go func() {
		defer close(out)
		defer func() {
			h.mu.Lock()
			delete(h.clients, live)
			n := len(h.clients)
			h.mu.Unlock()
			log.Printf("[hub] SSE client disconnected: clients=%d", n)
		}()
		for _, e := range snap {
			select {
			case out <- e:
			case <-ctx.Done():
				return
			}
		}
		for {
			select {
			case e := <-live:
				select {
				case out <- e:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func summarizeBuffer(buf []Event) string {
	if len(buf) == 0 {
		return "buffer empty"
	}
	counts := make(map[string]int, 8)
	for _, e := range buf {
		counts[e.Type]++
	}
	parts := make([]string, 0, len(counts))
	for t, n := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", t, n))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	want := strings.TrimSpace(r.URL.Query().Get("cluster"))

	ch := h.Subscribe(r.Context())
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()

	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return
			}
			if want != "" && want != "*" && e.Cluster != "" && e.Cluster != want {
				continue
			}
			b, _ := json.Marshal(e)
			if _, err := io.WriteString(w, "data: "+string(b)+"\n\n"); err != nil {
				return
			}
			fl.Flush()
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
