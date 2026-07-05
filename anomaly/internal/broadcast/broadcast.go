package broadcast

import "sync"

type Hub struct {
	mu   sync.RWMutex
	subs map[chan []byte]struct{}
}

func New() *Hub {
	return &Hub{subs: make(map[chan []byte]struct{})}
}

func (h *Hub) Subscribe() chan []byte {
	ch := make(chan []byte, 32)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *Hub) Broadcast(data []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subs {
		select {
		case ch <- data:
		default:
		}
	}
}
