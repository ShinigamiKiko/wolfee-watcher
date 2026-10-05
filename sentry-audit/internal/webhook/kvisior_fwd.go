package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	alertspkg "github.com/wolfee-watcher/pkg/alerts"
)

const (
	fwdQueueCap  = 1024
	fwdMaxBatch  = 64
	fwdAttempts  = 4
	fwdBackoff   = 2 * time.Second
	fwdDrainBudg = 10 * time.Second

	pathAuditEvents = "/internal/push/audit"
	pathAuditLog    = "/internal/push/audit-log"
	pathDelivery    = "/internal/pull/audit-delivery"
)

var ErrPermanent = alertspkg.ErrPermanentDelivery

type KvisiorForwarder struct {
	baseURL string
	pushURL string
	bodyKey string
	secret  string
	client  *http.Client

	q     *alertspkg.PushQueue[[]json.RawMessage]
	spool *alertspkg.DiskSpool

	ShedAt       float64
	ShedPerActor int
	shedMu       sync.Mutex
	windows      map[string]actorWindow
	shed         map[string]uint64
	shedTotal    uint64
	shedLogged   time.Time
}

type actorWindow struct {
	start time.Time
	count int
}

type DeliveryStatus struct {
	alertspkg.SpoolStatus
	Shed       uint64            `json:"shed"`
	ShedActors map[string]uint64 `json:"shedActors,omitempty"`
}

const (
	shedActorsTracked = 4096
	shedActorsShown   = 10
)

func newForwarder(name, pushURL, path, bodyKey, secret string, transport http.RoundTripper) *KvisiorForwarder {
	if pushURL == "" {
		return nil
	}
	f := &KvisiorForwarder{
		baseURL:      pushURL,
		pushURL:      pushURL + path,
		bodyKey:      bodyKey,
		secret:       secret,
		client:       &http.Client{Transport: transport, Timeout: 10 * time.Second},
		ShedAt:       0.8,
		ShedPerActor: 60,
		windows:      map[string]actorWindow{},
		shed:         map[string]uint64{},
	}
	f.q = alertspkg.NewPushQueue(name, fwdQueueCap, fwdMaxBatch,
		fwdAttempts, fwdBackoff, fwdDrainBudg, f.deliverBatch)
	return f
}

func NewKvisiorForwarder(pushURL, secret string, transport http.RoundTripper) *KvisiorForwarder {
	return newForwarder("kvisior-fwd/audit", pushURL, pathAuditEvents, "events", secret, transport)
}

func NewDurableForwarder(pushURL, secret, dir string, capacity int64, transport http.RoundTripper) (*KvisiorForwarder, error) {
	f := NewKvisiorForwarder(pushURL, secret, transport)
	if f == nil {
		return nil, fmt.Errorf("audit push URL is required")
	}
	spool, err := alertspkg.NewDiskSpool(filepath.Join(dir, "events"), capacity, func(ctx context.Context, batches []json.RawMessage) error {
		items := []json.RawMessage{}
		for _, raw := range batches {
			var batch []json.RawMessage
			if err := json.Unmarshal(raw, &batch); err != nil {
				return err
			}
			items = append(items, batch...)
		}
		return f.Send(ctx, items)
	})
	if err != nil {
		return nil, err
	}
	f.spool = spool
	return f, nil
}
func (f *KvisiorForwarder) Status() DeliveryStatus {
	if f == nil {
		return DeliveryStatus{}
	}
	var out DeliveryStatus
	if f.spool == nil {
		out.SpoolStatus = alertspkg.SpoolStatus{Rejected: uint64(f.q.Lost()), LastError: "durable spool unavailable"}
	} else {
		out.SpoolStatus = f.spool.Status()
	}
	f.shedMu.Lock()
	defer f.shedMu.Unlock()
	out.Shed = f.shedTotal
	if len(f.shed) > 0 {
		actors := make([]string, 0, len(f.shed))
		for actor := range f.shed {
			actors = append(actors, actor)
		}
		sort.Slice(actors, func(i, j int) bool { return f.shed[actors[i]] > f.shed[actors[j]] })
		out.ShedActors = map[string]uint64{}
		for _, actor := range actors[:min(len(actors), shedActorsShown)] {
			out.ShedActors[actor] = f.shed[actor]
		}
	}
	return out
}

func (f *KvisiorForwarder) admit(actor string, now time.Time) bool {
	if f.spool == nil || f.ShedAt <= 0 || f.ShedPerActor <= 0 {
		return true
	}
	status := f.spool.Status()
	if status.Capacity <= 0 || float64(status.Bytes+status.DeadBytes) < f.ShedAt*float64(status.Capacity) {
		return true
	}
	if actor == "" {
		actor = "unknown"
	}
	f.shedMu.Lock()
	defer f.shedMu.Unlock()
	w, ok := f.windows[actor]
	if !ok && len(f.windows) >= shedActorsTracked {
		for name, old := range f.windows {
			if now.Sub(old.start) >= time.Minute {
				delete(f.windows, name)
			}
		}
		if len(f.windows) >= shedActorsTracked {
			actor = "other"
			w = f.windows[actor]
		}
	}
	if now.Sub(w.start) >= time.Minute {
		w = actorWindow{start: now}
	}
	w.count++
	f.windows[actor] = w
	if w.count <= f.ShedPerActor {
		return true
	}
	f.shedTotal++
	if _, tracked := f.shed[actor]; tracked || len(f.shed) < shedActorsTracked {
		f.shed[actor]++
	} else {
		f.shed["other"]++
	}
	if now.Sub(f.shedLogged) >= time.Minute {
		f.shedLogged = now
		f.q.LogErrOnce("audit spool %.0f%% full: shedding events beyond %d per minute from %s (shed total %d)",
			100*float64(status.Bytes+status.DeadBytes)/float64(status.Capacity), f.ShedPerActor, actor, f.shedTotal)
	}
	return false
}

func NewLogForwarder(pushURL, secret string, transport http.RoundTripper) *KvisiorForwarder {
	return newForwarder("kvisior-fwd/audit-log", pushURL, pathAuditLog, "records", secret, transport)
}

func (f *KvisiorForwarder) Send(ctx context.Context, items []json.RawMessage) error {
	if f == nil {
		return fmt.Errorf("audit forwarder is not configured")
	}
	if len(items) == 0 {
		return nil
	}
	for start := 0; start < len(items); {
		end, size := start, 0
		for end < len(items) && end-start < 512 {
			if size+len(items[end])+1 > 2<<20 {
				break
			}
			size += len(items[end]) + 1
			end++
		}
		if end == start {
			return fmt.Errorf("%w: record too large", ErrPermanent)
		}
		switch result := f.deliverBatch(ctx, [][]json.RawMessage{items[start:end]}); result {
		case alertspkg.DeliveryOK:
		case alertspkg.DeliveryPermanent:
			return ErrPermanent
		default:
			return fmt.Errorf("audit delivery: %s", result)
		}
		start = end
	}
	return nil
}

func (f *KvisiorForwarder) Reachable(ctx context.Context) error {
	return f.Call(ctx, http.MethodGet, pathDelivery, nil, nil)
}

func (f *KvisiorForwarder) WakeOnReachable() {
	if f != nil && f.spool != nil {
		f.spool.SetProbe(f.Reachable)
	}
}

func (f *KvisiorForwarder) Call(ctx context.Context, method, path string, in, out any) error {
	if f == nil {
		return fmt.Errorf("audit forwarder is not configured")
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, f.baseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if f.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", f.secret)
		req.Header.Set("X-Cluster-ID", clusterID())
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("kvisior responded %d to %s %s", resp.StatusCode, method, path)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func (f *KvisiorForwarder) Forward(actor string, items []json.RawMessage) {
	if f == nil || len(items) == 0 {
		return
	}
	if f.spool != nil {
		if !f.admit(actor, time.Now()) {
			return
		}
		raw, err := json.Marshal(items)
		if err != nil {
			f.q.LogErrOnce("marshal audit event: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if err = f.spool.Enqueue(ctx, raw); err != nil {
			f.q.LogErrOnce("local audit durability unconfirmed: %v", err)
		}
		return
	}
	if !f.q.TryPush(items) {
		f.q.LogErrOnce("audit queue full")
	}
}

func (f *KvisiorForwarder) Close() {
	if f == nil {
		return
	}
	if f.spool != nil {
		f.spool.Close()
	}
	f.q.Close()
}

func (f *KvisiorForwarder) deliverBatch(ctx context.Context, batches [][]json.RawMessage) alertspkg.DeliveryResult {
	items := make([]json.RawMessage, 0, len(batches))
	for _, b := range batches {
		items = append(items, b...)
	}
	body, err := json.Marshal(map[string]interface{}{f.bodyKey: items})
	if err != nil {
		f.q.LogErrOnce("marshal failed for %d item(s): %v", len(items), err)
		return alertspkg.DeliveryPermanent
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, f.pushURL, bytes.NewReader(body))
	if err != nil {
		f.q.LogErrOnce("build request failed for %d item(s): %v", len(items), err)
		return alertspkg.DeliveryPermanent
	}
	req.Header.Set("Content-Type", "application/json")
	if f.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", f.secret)
		req.Header.Set("X-Cluster-ID", clusterID())
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.q.LogErrOnce("push failed: %v", err)
		return alertspkg.DeliveryRetry
	}

	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	result := alertspkg.ClassifyHTTPStatus(resp.StatusCode)
	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
		result = alertspkg.DeliveryRetry
	}
	if result != alertspkg.DeliveryOK {
		f.q.LogErrOnce("kvisior responded %d (%s)", resp.StatusCode, result)
	}
	return result
}

func clusterID() string {
	id := strings.TrimSpace(os.Getenv("CLUSTER_ID"))
	if id == "" {
		return "default"
	}
	return id
}
