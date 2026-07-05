package push

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/rules"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

type sysViolSSE struct {
	rules.Violation
	Fingerprint string `json:"fingerprint"`
}

type auditViolSSE struct {
	rules.AuditViolation
	Fingerprint string `json:"fingerprint"`
}

const maxConcurrentWrites = 50

const (
	maxPushBody        = 16 << 20
	maxSnapshotBody    = 64 << 20
	writeAcquireWait   = 2 * time.Second
	writeRequestTimout = 15 * time.Second
)

type Handler struct {
	hub          hub.Publisher
	localHub     hub.Publisher
	matcher      *rules.Matcher
	auditMatcher *rules.AuditMatcher
	store        *store.Store
	writeSem     chan struct{}
}

func New(pub, local hub.Publisher, m *rules.Matcher, am *rules.AuditMatcher, st *store.Store) *Handler {
	return &Handler{
		hub:          pub,
		localHub:     local,
		matcher:      m,
		auditMatcher: am,
		store:        st,
		writeSem:     make(chan struct{}, maxConcurrentWrites),
	}
}

func (h *Handler) syncWrite(w http.ResponseWriter, r *http.Request, what string, fn func(context.Context) error) bool {
	if h.store == nil {
		http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
		return false
	}

	acquireCtx, cancelAcquire := context.WithTimeout(r.Context(), writeAcquireWait)
	defer cancelAcquire()
	select {
	case h.writeSem <- struct{}{}:
		defer func() { <-h.writeSem }()
	case <-acquireCtx.Done():
		slog.Warn("push_write_backlog_full",
			"component", "kvisior/push",
			"kind", what,
			"inflight", len(h.writeSem),
			"limit", cap(h.writeSem),
			"error", acquireCtx.Err())
		http.Error(w, `{"error":"write backlog full"}`, http.StatusServiceUnavailable)
		return false
	}

	ctx, cancel := context.WithTimeout(r.Context(), writeRequestTimout)
	defer cancel()
	if err := fn(ctx); err != nil {
		slog.Error("push_persist_failed",
			"component", "kvisior/push",
			"kind", what,
			"timeout", ctx.Err() != nil,
			"error", err)
		if ctx.Err() != nil {
			http.Error(w, `{"error":"write timeout"}`, http.StatusServiceUnavailable)
			return false
		}
		http.Error(w, `{"error":"write failed"}`, http.StatusInternalServerError)
		return false
	}
	return true
}

func (h *Handler) HandleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPushBody)
	var body struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, raw := range body.Events {
		var ev map[string]interface{}
		if json.Unmarshal(raw, &ev) == nil {

			if sc, _ := ev["syscall"].(string); h.matcher.AllowsLiveStream(sc) {
				h.hub.Publish(hub.Event{Type: "tracee_event", Data: raw})
			}
			for _, v := range h.matcher.Match(ev) {
				ns, _ := ev["namespace"].(string)
				pod, _ := ev["pod"].(string)
				fp := store.Fingerprint(v.RuleID, ns, pod, time.Now())
				ruleID, ruleName, sev := v.RuleID, v.Rule, v.Sev
				rawCopy := append(json.RawMessage(nil), raw...)
				if !h.syncWrite(w, r, "syscall violation", func(ctx context.Context) error {
					return h.store.WriteViolationChecked(ctx, "syscall", ruleID, ruleName, sev, ns, pod, fp, rawCopy)
				}) {
					return
				}
				sseData, _ := json.Marshal(sysViolSSE{Violation: v, Fingerprint: fp})
				h.hub.Publish(hub.Event{Type: "violation", Data: sseData})
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPushBody)
	var body struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, raw := range body.Events {
		rawEv := append(json.RawMessage(nil), raw...)
		if !h.syncWrite(w, r, "audit event", func(ctx context.Context) error {
			return h.store.InsertAuditEvent(ctx, rawEv)
		}) {
			return
		}
		h.hub.Publish(hub.Event{Type: "audit_event", Data: raw})

		var ev map[string]interface{}
		if json.Unmarshal(raw, &ev) == nil {
			for _, v := range h.auditMatcher.Match(ev) {
				evTs := time.Now()
				if t, err := time.Parse(time.RFC3339, v.Timestamp); err == nil {
					evTs = t
				}
				fp := store.Fingerprint(v.RuleID, v.Namespace, v.Name, evTs)
				ruleID, policy, sev, ns, name := v.RuleID, v.Policy, v.Sev, v.Namespace, v.Name
				rawCopy := append(json.RawMessage(nil), raw...)
				if !h.syncWrite(w, r, "audit violation", func(ctx context.Context) error {
					return h.store.WriteViolationChecked(ctx, "audit", ruleID, policy, sev, ns, name, fp, rawCopy)
				}) {
					return
				}
				sseData, _ := json.Marshal(auditViolSSE{AuditViolation: v, Fingerprint: fp})
				h.hub.Publish(hub.Event{Type: "audit_violation", Data: sseData})
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleSensorSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSnapshotBody)
	var snapshot json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&snapshot); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.localHub.Publish(hub.Event{Type: "sensor_snapshot", Data: snapshot})
	slog.Info("sensor_snapshot_ingested",
		"component", "kvisior/push",
		"bytes", len(snapshot))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleAnomalyEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPushBody)
	var body struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, raw := range body.Events {
		h.hub.Publish(hub.Event{Type: "anomaly_event", Data: raw})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleHoneypotEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPushBody)
	var body struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, raw := range body.Events {
		var ev honeypotEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			continue
		}
		ev.ID = honeypotEventID(ev)

		enriched, err := json.Marshal(ev)
		if err != nil {
			enriched = raw
		}
		if ev.HoneypotName != "" && ev.Namespace != "" {
			ns, name, id, ts := ev.Namespace, ev.HoneypotName, ev.ID, ev.Timestamp
			data := append(json.RawMessage(nil), enriched...)
			if !h.syncWrite(w, r, "honeypot event", func(ctx context.Context) error {
				return h.store.WriteHoneypotEvent(ctx, ns, name, id, ts, data)
			}) {
				return
			}
		}
		h.hub.Publish(hub.Event{Type: "honeypot_event", Data: enriched})
		slog.Info("honeypot_hit",
			"component", "kvisior/push",
			"honeypot", ev.HoneypotName,
			"src_ip", ev.SrcIP,
			"server", ev.Server)
	}
	w.WriteHeader(http.StatusNoContent)
}

type honeypotEvent struct {
	ID           string `json:"id"`
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

func honeypotEventID(ev honeypotEvent) string {
	raw := strings.Join([]string{
		ev.Timestamp, ev.Server, ev.SrcIP, ev.SrcPort,
		ev.DestIP, ev.DestPort, ev.Action, ev.Status,
		ev.Data, ev.Username, ev.Password,
	}, "\x1f")
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (h *Handler) HandleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSnapshotBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var meta struct {
		Image     string    `json:"image"`
		ScannedAt time.Time `json:"scannedAt"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if meta.Image == "" {
		http.Error(w, `{"error":"image required"}`, http.StatusBadRequest)
		return
	}
	scannedAt := meta.ScannedAt
	if scannedAt.IsZero() {
		scannedAt = time.Now()
	}
	data := append(json.RawMessage(nil), raw...)
	if !h.syncWrite(w, r, "image scan", func(ctx context.Context) error {
		return h.store.UpsertImageScan(ctx, meta.Image, scannedAt, data)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleAuditRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSnapshotBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var meta struct {
		Tool      string    `json:"tool"`
		RunID     string    `json:"runId"`
		Status    string    `json:"status"`
		StartedAt time.Time `json:"startedAt"`
		DoneAt    time.Time `json:"doneAt"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if meta.Tool != "bench" && meta.Tool != "hunter" {
		http.Error(w, `{"error":"tool must be bench or hunter"}`, http.StatusBadRequest)
		return
	}
	data := append(json.RawMessage(nil), raw...)
	if !h.syncWrite(w, r, "audit run", func(ctx context.Context) error {
		return h.store.InsertAuditRun(ctx, meta.Tool, meta.RunID, meta.Status, meta.StartedAt, meta.DoneAt, data)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleHistories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSnapshotBody)
	var body struct {
		Histories []json.RawMessage `json:"histories"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	items := body.Histories
	if !h.syncWrite(w, r, "image history", func(ctx context.Context) error {
		for _, raw := range items {
			var meta struct {
				Image string `json:"image"`
			}
			if json.Unmarshal(raw, &meta) != nil || meta.Image == "" {
				continue
			}
			if err := h.store.UpsertImageHistory(ctx, meta.Image, raw); err != nil {
				return err
			}
		}
		return nil
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleForensicEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPushBody)
	var body struct {
		NS      string                `json:"ns"`
		Pod     string                `json:"pod"`
		Entries []store.ForensicEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.NS == "" || body.Pod == "" || len(body.Entries) == 0 {
		http.Error(w, `{"error":"ns, pod and entries required"}`, http.StatusBadRequest)
		return
	}
	if h.store == nil {
		http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := h.store.InsertForensicEvents(ctx, body.NS, body.Pod, body.Entries); err != nil {
		slog.Error("forensic_events_insert_failed",
			"component", "kvisior/push",
			"namespace", body.NS,
			"pod", body.Pod,
			"error", err)
		http.Error(w, `{"error":"insert failed"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleForensicWatch(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("ns")
	pod := r.URL.Query().Get("pod")
	if ns == "" || pod == "" {
		http.Error(w, `{"error":"ns and pod required"}`, http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPost:
		if !h.syncWrite(w, r, "forensic watch", func(ctx context.Context) error {
			return h.store.UpsertForensicWatch(ctx, ns, pod)
		}) {
			return
		}
	case http.MethodDelete:
		if !h.syncWrite(w, r, "forensic watch", func(ctx context.Context) error {
			return h.store.DeleteForensicWatch(ctx, ns, pod)
		}) {
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleForensicDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ns := r.URL.Query().Get("ns")
	pod := r.URL.Query().Get("pod")
	if ns == "" || pod == "" {
		http.Error(w, `{"error":"ns and pod required"}`, http.StatusBadRequest)
		return
	}
	if h.store == nil {
		http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	entries, err := h.store.QueryForensicEvents(ctx, ns, pod)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"entries": entries})
}

func (h *Handler) HandleAlertRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.store == nil {
		http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rules, err := h.store.LoadAlertRules(ctx, r.URL.Query().Get("detType"))
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"policies": rules})
}

func (h *Handler) HandleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSnapshotBody)
	var body struct {
		NS        string `json:"ns"`
		Pod       string `json:"pod"`
		Container string `json:"container"`

		Node    string                    `json:"node"`
		Entries []store.ContainerLogEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.NS == "" || body.Pod == "" || body.Container == "" || len(body.Entries) == 0 {
		http.Error(w, `{"error":"ns, pod, container and entries required"}`, http.StatusBadRequest)
		return
	}
	if h.store == nil {
		http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := h.store.InsertContainerLogEntries(ctx, body.Node, body.NS, body.Pod, body.Container, body.Entries); err != nil {
		slog.Error("container_logs_insert_failed",
			"component", "kvisior/push",
			"node", body.Node,
			"namespace", body.NS,
			"pod", body.Pod,
			"container", body.Container,
			"error", err)
		http.Error(w, `{"error":"insert failed"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleLogsPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.store == nil {
		http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	ns, pod, container := q.Get("ns"), q.Get("pod"), q.Get("container")
	sinceSeconds, _ := strconv.ParseInt(q.Get("sinceSeconds"), 10, 64)
	if ns == "" || pod == "" || container == "" || sinceSeconds <= 0 {
		http.Error(w, `{"error":"ns, pod, container and sinceSeconds required"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	lines, err := h.store.QueryContainerLogs(ctx, ns, pod, container, sinceSeconds)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"lines": lines})
}

func (h *Handler) HandleLogCursors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.store == nil {
		http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	cursors, err := h.store.LoadLogCursors(ctx, r.URL.Query().Get("node"))
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"cursors": cursors})
}

const snapshotCacheKey = "cluster-snapshot-gzip"

func (h *Handler) HandleSnapshotCachePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	etag := r.URL.Query().Get("etag")
	if etag == "" {
		http.Error(w, `{"error":"etag required"}`, http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSnapshotBody))
	if err != nil || len(data) == 0 {
		http.Error(w, `{"error":"body required"}`, http.StatusBadRequest)
		return
	}
	body := append([]byte(nil), data...)
	if !h.syncWrite(w, r, "snapshot cache", func(ctx context.Context) error {
		return h.store.PutSnapshotCache(ctx, snapshotCacheKey, body, etag)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleSnapshotCachePull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.store == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	data, etag, err := h.store.GetSnapshotCache(ctx, snapshotCacheKey)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("X-Snapshot-ETag", etag)
	w.Write(data)
}

func (h *Handler) HandleIntegrationPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		http.Error(w, `{"error":"kind required"}`, http.StatusBadRequest)
		return
	}
	if h.store == nil {
		http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	cfg, ok, err := h.store.GetEnabledIntegration(ctx, kind)
	if err != nil {
		slog.Error("integration_pull_failed",
			"component", "kvisior/push",
			"kind", kind,
			"error", err)
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(cfg)
}

func (h *Handler) HandleScannerStatePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSnapshotBody)
	var body struct {
		Key  string          `json:"key"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Key == "" || len(body.Data) == 0 {
		http.Error(w, `{"error":"key and data required"}`, http.StatusBadRequest)
		return
	}
	key, data := body.Key, append(json.RawMessage(nil), body.Data...)
	if !h.syncWrite(w, r, "scanner state", func(ctx context.Context) error {
		return h.store.PutScannerState(ctx, key, data)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleScannerStatePull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, `{"error":"key required"}`, http.StatusBadRequest)
		return
	}
	if h.store == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	data, ok, err := h.store.GetScannerState(ctx, key)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
