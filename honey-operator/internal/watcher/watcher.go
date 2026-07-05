package watcher

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	k8sclient "github.com/wolfee-watcher/honey-operator/internal/k8s"
)

type Event struct {
	HoneypotName string `json:"honeypotName"`
	Namespace    string `json:"namespace"`
	Timestamp    string `json:"timestamp"`
	Server       string `json:"server"`
	SrcIP        string `json:"src_ip"`
	SrcPort      string `json:"src_port"`
	DestIP       string `json:"dest_ip,omitempty"`
	DestPort     string `json:"dest_port"`
	Action       string `json:"action"`
	Status       string `json:"status,omitempty"`
	Data         string `json:"data,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
}

type rawEvent struct {
	Timestamp string `json:"timestamp"`
	Server    string `json:"server"`
	SrcIP     string `json:"src_ip"`
	SrcPort   string `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  string `json:"dest_port"`
	Action    string `json:"action"`
	Status    string `json:"status"`
	Data      string `json:"data"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type Watcher struct {
	manager *k8sclient.Manager
	mu      sync.RWMutex
	seen    map[string]string
	subs    map[chan []byte]struct{}
	fwd     *kvisiorForwarder
}

func New(manager *k8sclient.Manager, pushURL, secret string) *Watcher {
	return &Watcher{
		manager: manager,
		seen:    make(map[string]string),
		subs:    make(map[chan []byte]struct{}),
		fwd:     newKvisiorForwarder(pushURL, secret),
	}
}

func (w *Watcher) Close() {
	w.fwd.close()
}

func (w *Watcher) Subscribe() chan []byte {
	ch := make(chan []byte, 64)
	w.mu.Lock()
	w.subs[ch] = struct{}{}
	w.mu.Unlock()
	return ch
}

func (w *Watcher) Unsubscribe(ch chan []byte) {
	w.mu.Lock()
	delete(w.subs, ch)
	w.mu.Unlock()
	close(ch)
}

func (w *Watcher) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Printf("[watcher] started, poll interval=%s", interval)
	w.poll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.poll(ctx)
		}
	}
}

func (w *Watcher) poll(ctx context.Context) {
	pods, err := w.manager.List(ctx, "")
	if err != nil {
		log.Printf("[watcher] list honeypot pods error: %v", err)
		return
	}
	for _, pod := range pods {
		userName := pod.Labels["honeypot-name"]
		if userName == "" {

			userName = strings.TrimPrefix(pod.Name, "h-")
		}
		ns := pod.Namespace
		key := ns + "/" + userName

		raw, err := w.manager.Logs(ctx, userName, ns, 500)
		if err != nil {
			log.Printf("[watcher] logs error %s/%s: %v", ns, userName, err)
			continue
		}

		w.mu.RLock()
		lastSeen := w.seen[key]
		w.mu.RUnlock()

		newEvents, latestTS := parseNewEvents(raw, lastSeen)
		if len(newEvents) == 0 {
			continue
		}

		w.mu.Lock()
		w.seen[key] = latestTS
		w.mu.Unlock()

		for _, ev := range newEvents {

			log.Printf("[honeypot-hit] %s/%s server=%s action=%s status=%s src=%s:%s dst_port=%s",
				ns, userName, ev.Server, ev.Action, ev.Status, ev.SrcIP, ev.SrcPort, ev.DestPort)
			out := Event{
				HoneypotName: userName,
				Namespace:    ns,
				Timestamp:    ev.Timestamp,
				Server:       ev.Server,
				SrcIP:        ev.SrcIP,
				SrcPort:      ev.SrcPort,
				DestIP:       ev.DestIP,
				DestPort:     ev.DestPort,
				Action:       ev.Action,
				Status:       ev.Status,
				Data:         ev.Data,
				Username:     ev.Username,
				Password:     ev.Password,
			}
			b, err := json.Marshal(out)
			if err != nil {
				continue
			}
			w.broadcast(b)
		}
	}
}

func (w *Watcher) broadcast(payload []byte) {
	w.fwd.forward(payload)
	w.mu.RLock()
	defer w.mu.RUnlock()
	for ch := range w.subs {
		select {
		case ch <- payload:
		default:
		}
	}
}

func parseNewEvents(raw []byte, lastSeen string) ([]rawEvent, string) {
	var events []rawEvent
	latestTS := lastSeen

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev rawEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Action == "process" && ev.SrcIP == "0.0.0.0" {
			continue
		}
		if lastSeen == "" || ev.Timestamp > lastSeen {
			events = append(events, ev)
			if ev.Timestamp > latestTS {
				latestTS = ev.Timestamp
			}
		}
	}
	return events, latestTS
}
