package watcher

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8sclient "github.com/wolfee-watcher/honey-operator/internal/k8s"
	"github.com/wolfee-watcher/honey-operator/internal/registry"
)

const (
	initialTail   = 500
	reconnectWait = 3 * time.Second
	seenCap       = 20000
)

type Event struct {
	HoneypotID   string `json:"honeypotId,omitempty"`
	HoneypotName string `json:"honeypotName"`
	Namespace    string `json:"namespace"`
	Kind         string `json:"kind,omitempty"`
	Service      string `json:"service,omitempty"`
	Pod          string `json:"pod,omitempty"`
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

type target struct {
	id, name, namespace, kind, service, pod string
}

type Watcher struct {
	manager *k8sclient.Manager
	reg     *registry.Client

	mu      sync.RWMutex
	subs    map[chan []byte]struct{}
	records []registry.Record
	fwd     *kvisiorForwarder

	streamMu sync.Mutex
	streams  map[string]context.CancelFunc

	seenMu    sync.Mutex
	seen      map[string]struct{}
	seenOrder []string
}

func New(manager *k8sclient.Manager, reg *registry.Client, pushURL, secret string) *Watcher {
	return &Watcher{
		manager: manager,
		reg:     reg,
		subs:    make(map[chan []byte]struct{}),
		fwd:     newKvisiorForwarder(pushURL, secret),
		streams: make(map[string]context.CancelFunc),
		seen:    make(map[string]struct{}),
	}
}

func (w *Watcher) Close() {
	w.streamMu.Lock()
	for _, cancel := range w.streams {
		cancel()
	}
	w.streamMu.Unlock()
	w.fwd.close()
}

func (w *Watcher) Records() []registry.Record {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]registry.Record, len(w.records))
	copy(out, w.records)
	return out
}

func (w *Watcher) SetRecords(recs []registry.Record) {
	w.mu.Lock()
	w.records = recs
	w.mu.Unlock()
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
	log.Printf("[watcher] started, refresh interval=%s", interval)
	w.refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.refresh(ctx)
		}
	}
}

func (w *Watcher) Refresh(ctx context.Context) { w.refresh(ctx) }

func (w *Watcher) refresh(ctx context.Context) {
	if w.reg.Enabled() {
		if recs, err := w.reg.List(ctx); err != nil {
			log.Printf("[watcher] registry list: %v (keeping %d known honeypots)", err, len(w.Records()))
		} else {
			w.SetRecords(recs)
		}
	}

	want := map[string]target{}
	for _, rec := range w.Records() {
		for _, pod := range w.manager.OwnedPods(ctx, rec) {
			want[string(pod.UID)] = target{id: rec.ID, name: rec.Name, namespace: rec.Namespace, kind: rec.Kind, service: rec.Service, pod: pod.Name}
		}
	}
	if legacy, err := w.manager.List(ctx, ""); err == nil {
		for _, pod := range legacy {
			name := pod.Labels["honeypot-name"]
			if name == "" {
				name = strings.TrimPrefix(pod.Name, "h-")
			}
			want[string(pod.UID)] = target{name: name, namespace: pod.Namespace, kind: "Pod", pod: pod.Name}
		}
	}

	w.streamMu.Lock()
	defer w.streamMu.Unlock()
	for uid, cancel := range w.streams {
		if _, ok := want[uid]; !ok {
			cancel()
			delete(w.streams, uid)
		}
	}
	for uid, t := range want {
		if _, ok := w.streams[uid]; ok {
			continue
		}
		sctx, cancel := context.WithCancel(ctx)
		w.streams[uid] = cancel
		go w.follow(sctx, t)
	}
}

func (w *Watcher) follow(ctx context.Context, t target) {
	var since *metav1.Time
	for ctx.Err() == nil {
		opened := time.Now()
		stream, err := w.manager.StreamLogs(ctx, t.namespace, t.pod, since, initialTail)
		if err == nil {
			scanner := bufio.NewScanner(stream)
			scanner.Buffer(make([]byte, 64*1024), 1<<20)
			for scanner.Scan() {
				w.handleLine(t, scanner.Bytes())
			}
			stream.Close()
		}
		ts := metav1.NewTime(opened)
		since = &ts
		select {
		case <-ctx.Done():
			return
		case <-time.After(reconnectWait):
		}
	}
}

func (w *Watcher) handleLine(t target, line []byte) {
	s := strings.TrimSpace(string(line))
	if !strings.HasPrefix(s, "{") {
		return
	}
	var ev rawEvent
	if err := json.Unmarshal([]byte(s), &ev); err != nil {
		return
	}
	if ev.Action == "process" && ev.SrcIP == "0.0.0.0" {
		return
	}
	key := t.namespace + "\x1f" + t.name + "\x1f" + t.pod + "\x1f" + s
	if !w.firstSeen(key) {
		return
	}
	out := Event{
		HoneypotID:   t.id,
		HoneypotName: t.name,
		Namespace:    t.namespace,
		Kind:         t.kind,
		Service:      t.service,
		Pod:          t.pod,
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
	log.Printf("[honeypot-hit] %s/%s pod=%s server=%s action=%s src=%s:%s", t.namespace, t.name, t.pod, ev.Server, ev.Action, ev.SrcIP, ev.SrcPort)
	b, err := json.Marshal(out)
	if err != nil {
		return
	}
	w.broadcast(b)
}

func (w *Watcher) firstSeen(key string) bool {
	sum := sha256.Sum256([]byte(key))
	id := hex.EncodeToString(sum[:])
	w.seenMu.Lock()
	defer w.seenMu.Unlock()
	if _, ok := w.seen[id]; ok {
		return false
	}
	w.seen[id] = struct{}{}
	w.seenOrder = append(w.seenOrder, id)
	if len(w.seenOrder) > seenCap {
		drop := w.seenOrder[:len(w.seenOrder)-seenCap]
		for _, d := range drop {
			delete(w.seen, d)
		}
		w.seenOrder = append([]string(nil), w.seenOrder[len(drop):]...)
	}
	return true
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
