package auditdelivery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/auditengine"
	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

const MaxAuditBody = 4 << 20

type Receiver struct {
	Store       *store.Store
	MaxPending  int
	PerCluster  int
	BudgetBytes int64
	writes      chan struct{}
	mu          sync.Mutex
	active      map[string]int
	reserved    int64
}

func NewReceiver(st *store.Store, maxPending int) *Receiver {
	return &Receiver{Store: st, MaxPending: maxPending, PerCluster: 4, BudgetBytes: 24 << 20, writes: make(chan struct{}, 16), active: map[string]int{}}
}

func (h *Receiver) acquire(cluster string, size int64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.PerCluster > 0 && h.active[cluster] >= h.PerCluster {
		return false
	}
	if h.BudgetBytes > 0 && h.reserved+size > h.BudgetBytes {
		return false
	}
	select {
	case h.writes <- struct{}{}:
	default:
		return false
	}
	h.active[cluster]++
	h.reserved += size
	return true
}

func (h *Receiver) release(cluster string, size int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	<-h.writes
	h.reserved -= size
	if h.active[cluster]--; h.active[cluster] <= 0 {
		delete(h.active, cluster)
	}
}

type readTracker struct {
	r   io.Reader
	err error
}

func (t *readTracker) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF && t.err == nil {
		t.err = err
	}
	return n, err
}

func (h *Receiver) Events(w http.ResponseWriter, r *http.Request) { h.receive(w, r, "events") }
func (h *Receiver) Log(w http.ResponseWriter, r *http.Request)    { h.receive(w, r, "log") }
func (h *Receiver) Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.Store == nil {
		http.Error(w, "audit inbox unavailable", 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	status, err := h.Store.AuditInboxStatus(ctx)
	if err != nil {
		http.Error(w, "audit inbox unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
func (h *Receiver) receive(w http.ResponseWriter, r *http.Request, kind string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cluster := clusterctx.ForPush(r)
	if !store.ValidClusterID(cluster) {
		slog.Warn("audit_batch_without_cluster", "component", "kvisior/audit-delivery", "remote", r.RemoteAddr, "kind", kind)
		http.Error(w, "cluster identity required", http.StatusForbidden)
		return
	}
	if r.ContentLength > MaxAuditBody {
		http.Error(w, "audit batch too large", 413)
		return
	}
	if h.Store == nil {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "audit inbox unavailable", 503)
		return
	}
	size := int64(MaxAuditBody)
	if r.ContentLength > 0 {
		size = r.ContentLength
	}
	if !h.acquire(cluster, size) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "audit receiver busy", 503)
		return
	}
	defer h.release(cluster, size)
	source := &readTracker{r: http.MaxBytesReader(w, r.Body, MaxAuditBody)}
	var body struct {
		Events  []json.RawMessage `json:"events"`
		Records []json.RawMessage `json:"records"`
	}
	decoder := json.NewDecoder(source)
	err := decoder.Decode(&body)
	if err == nil {
		if extra := decoder.Decode(new(any)); extra != io.EOF {
			err = extra
			if extra == nil {
				err = errors.New("one audit batch required")
			}
		}
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(source.err, &tooLarge):
			http.Error(w, "audit batch too large", http.StatusRequestEntityTooLarge)
		case source.err != nil || errors.Is(err, io.ErrUnexpectedEOF):
			slog.Warn("audit_batch_read_failed", "component", "kvisior/audit-delivery", "cluster", cluster, "kind", kind, "error", err)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "audit batch was not received completely", http.StatusServiceUnavailable)
		default:
			http.Error(w, "invalid audit batch", http.StatusBadRequest)
		}
		return
	}
	records := body.Events
	if kind == "log" {
		records = body.Records
	}
	if len(records) > 512 {
		http.Error(w, "audit batch too large", 413)
		return
	}
	for _, raw := range records {
		if len(raw) == 0 || raw[0] != '{' {
			http.Error(w, "audit record must be an object", 400)
			return
		}
		if kind == "events" {
			var ev auditrules.Event
			if json.Unmarshal(raw, &ev) != nil {
				http.Error(w, "invalid audit event", 400)
				return
			}
		} else {
			var rec auditengine.LogRecord
			if json.Unmarshal(raw, &rec) != nil {
				http.Error(w, "invalid audit log record", 400)
				return
			}
		}
	}
	if len(records) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	err = h.Store.EnqueueAudit(ctx, cluster, kind, records, h.MaxPending)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusAccepted)
	case store.IsDataError(err):
		slog.Warn("audit_batch_rejected", "component", "kvisior/audit-delivery", "cluster", cluster, "kind", kind, "records", len(records), "error", err)
		http.Error(w, "audit batch rejected by the database", 400)
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "audit inbox unavailable or full", 503)
	}
}

type Processor interface {
	IngestEvents(context.Context, string, []json.RawMessage) error
	IngestLog(context.Context, string, []auditengine.LogRecord) error
}

func Process(ctx context.Context, engine Processor, batch store.AuditBatch) error {
	if batch.Kind == "events" {
		raws := make([]json.RawMessage, 0, len(batch.Payload))
		for _, raw := range batch.Payload {
			var ev auditrules.Event
			if err := json.Unmarshal(raw, &ev); err != nil {
				unreadable(batch, err)
				continue
			}
			stableEvent(&ev, raw, batch)
			normalized, err := json.Marshal(ev)
			if err != nil {
				return err
			}
			raws = append(raws, normalized)
		}
		return engine.IngestEvents(ctx, batch.Cluster, raws)
	}
	if batch.Kind != "log" {
		return fmt.Errorf("unknown audit batch kind %q", batch.Kind)
	}
	records := make([]auditengine.LogRecord, 0, len(batch.Payload))
	for _, raw := range batch.Payload {
		var rec auditengine.LogRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			unreadable(batch, err)
			continue
		}
		stableEvent(&rec.Event, raw, batch)
		records = append(records, rec)
	}
	return engine.IngestLog(ctx, batch.Cluster, records)
}
func unreadable(batch store.AuditBatch, err error) {
	slog.Error("audit_record_unreadable", "component", "kvisior/audit-delivery", "cluster", batch.Cluster, "batch", batch.ID, "kind", batch.Kind, "error", err)
}

func stableEvent(ev *auditrules.Event, raw json.RawMessage, batch store.AuditBatch) {
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("inbox-%x", sha256.Sum256(append([]byte(batch.Cluster+"\x00"), raw...)))
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = batch.CreatedAt
	}
}

func Run(ctx context.Context, st *store.Store, engine Processor, workers int) {
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			failures := 0
			for ctx.Err() == nil {
				jobCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				worked, err := st.ProcessAuditBatch(jobCtx, func(ctx context.Context, b store.AuditBatch) error { return Process(ctx, engine, b) })
				cancel()
				if err != nil {
					failures++
					if failures == 1 || failures%30 == 0 {
						slog.Warn("audit_inbox_retry", "error", err, "consecutive", failures)
					}
				} else {
					failures = 0
				}
				if worked && err == nil {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
		}()
	}
	defer wg.Wait()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			if removed, err := st.CleanAuditInbox(cleanCtx); err != nil {
				slog.Warn("audit_inbox_retention_failed", "component", "kvisior/audit-delivery", "removed", removed, "error", err)
			} else if removed > 0 {
				slog.Info("audit_inbox_retention", "component", "kvisior/audit-delivery", "removed", removed)
			}
			cancel()
		}
	}
}
