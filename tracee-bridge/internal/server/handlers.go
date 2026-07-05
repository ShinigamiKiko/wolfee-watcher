package server

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wolfee-watcher/tracee-bridge/internal/k8s"
)

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"service": "tracee-bridge",
		"uptime":  time.Since(s.startTime).Round(time.Second).String(),
		"pg_mode": s.hub.PGMode(),
	})
}

func (s *Server) recordIngestLatencyMs(ms int64) {
	for i, bound := range histBoundsMs {
		if ms <= bound {
			s.ingestHist[i].Add(1)
			return
		}
	}
	s.ingestHist[len(histBoundsMs)].Add(1)
}

func (s *Server) computeIngestP99() float64 {
	var counts [11]int64
	var total int64
	for i := range counts {
		counts[i] = s.ingestHist[i].Load()
		total += counts[i]
	}
	if total == 0 {
		return 0
	}
	target := int64(math.Ceil(float64(total) * 0.99))
	var cum int64
	for i, c := range counts {
		cum += c
		if cum >= target {
			if i < len(histBoundsMs) {
				return float64(histBoundsMs[i])
			}
			return float64(histBoundsMs[len(histBoundsMs)-1]) * 2
		}
	}
	return float64(histBoundsMs[len(histBoundsMs)-1]) * 2
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	ingestReqs := s.ingestReqs.Load()
	ingestLatencyNs := s.ingestLatencyNanos.Load()
	queryReqs := s.queryReqs.Load()
	queryLatencyNs := s.queryLatencyNanos.Load()
	ingestAvgMs := 0.0
	queryAvgMs := 0.0
	if ingestReqs > 0 {
		ingestAvgMs = float64(ingestLatencyNs) / float64(ingestReqs) / float64(time.Millisecond)
	}
	if queryReqs > 0 {
		queryAvgMs = float64(queryLatencyNs) / float64(queryReqs) / float64(time.Millisecond)
	}
	queueLen := len(s.eventQueue)
	queueCap := cap(s.eventQueue)
	queueFillPct := 0.0
	if queueCap > 0 {
		queueFillPct = float64(queueLen) / float64(queueCap) * 100.0
	}
	kafkaBufRecs, kafkaBufBytes := s.hub.KafkaProducerBuffered()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"events_total":           s.eventsTotal.Load(),
		"events_accepted":        s.eventsAccepted.Load(),
		"events_rejected":        s.eventsRejected.Load(),
		"events_rate_limited":    s.eventsRateLimited.Load(),
		"events_busy":            s.eventsBusy.Load(),
		"events_dropped":         s.eventsDropped.Load(),
		"events_overflow":        s.eventsOverflow.Load(),
		"query_timeouts":         s.queryTimeouts.Load(),
		"ingest_avg_ms":          ingestAvgMs,
		"query_avg_ms":           queryAvgMs,
		"sse_drops":              s.hub.SSEDrops(),
		"sse_evictions":          s.hub.SSEEvictions(),
		"clients":                s.hub.ClientCount(),
		"history":                s.hub.HistoryLen(),
		"pg_mode":                s.hub.PGMode(),
		"uptime_sec":             int64(time.Since(s.startTime).Seconds()),
		"ingest_queue_len":       queueLen,
		"ingest_queue_cap":       queueCap,
		"ingest_queue_pct":       queueFillPct,
		"ingest_workers":         s.ingestWorkers,
		"hub_received":           s.hub.Received(),
		"hub_passed":             s.hub.Passed(),
		"hub_dropped":            s.hub.HubDropped(),
		"dedup_skipped":          s.hub.DedupSkipped(),
		"kafka_topic":            s.hub.KafkaTopic(),
		"kafka_buffered_records": kafkaBufRecs,
		"kafka_buffered_bytes":   kafkaBufBytes,
		"ingest_p99_ms":          s.computeIngestP99(),
	})
}

func (s *Server) handleComponents(w http.ResponseWriter, _ *http.Request) {
	type entry struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		NS    string `json:"namespace"`
		Name  string `json:"name"`
		Kind  string `json:"kind"`
		Alive int32  `json:"alive"`
		Total int32  `json:"total"`
		Found bool   `json:"found"`
	}

	ns := currentNamespace()
	out := make([]entry, 0, len(defaultComponents()))
	for _, parts := range configuredComponents() {
		st := s.podCache.ComponentStatus(ns, parts[3], parts[2])
		out = append(out, entry{
			ID:    parts[0],
			Label: parts[1],
			NS:    ns,
			Name:  parts[3],
			Kind:  parts[2],
			Alive: st.Alive,
			Total: st.Total,
			Found: st.Found,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"components": out})
}

func (s *Server) handleK8sMetrics(w http.ResponseWriter, _ *http.Request) {
	comps := make([]k8s.ComponentSpec, 0, len(defaultComponents()))
	for _, parts := range configuredComponents() {
		comps = append(comps, k8s.ComponentSpec{ID: parts[0], Label: parts[1], Kind: parts[2], Name: parts[3]})
	}
	result := s.podCache.K8sMetrics(currentNamespace(), comps)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleKafkaStats(w http.ResponseWriter, r *http.Request) {
	result := s.hub.KafkaAdminStats(r.Context())
	result.Postgres = s.hub.PGMetrics(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleEventsQuery(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		s.queryLatencyNanos.Add(time.Since(start).Nanoseconds())
		s.queryReqs.Add(1)
	}()

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rlKey := strings.TrimSpace(r.Header.Get("X-Acting-User"))
	if rlKey == "" {
		rlKey = clientIP(r)
	}
	if !s.queryLimiter.Allow(rlKey) {
		s.eventsRejected.Add(1)
		s.eventsRateLimited.Add(1)
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	select {
	case s.querySem <- struct{}{}:
		defer func() { <-s.querySem }()
	default:
		s.eventsRejected.Add(1)
		s.eventsBusy.Add(1)
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	hours := 6
	if v := q.Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			hours = n
		}
	}
	limit := int64(20000)
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 50000 {
		limit = 50000
	}

	nsFilter := q.Get("namespace")
	podFilter := q.Get("pod")
	containerFilter := q.Get("container")

	ctx, cancel := context.WithTimeout(r.Context(), s.queryTimeout)
	defer cancel()
	type queryResult struct {
		raw       [][]byte
		truncated bool
		err       error
	}
	resCh := make(chan queryResult, 1)
	go func() {
		raw, truncated, err := s.hub.GetWindowHistory(hours, limit)
		resCh <- queryResult{raw: raw, truncated: truncated, err: err}
	}()

	var (
		rawEvents [][]byte
		truncated bool
	)
	select {
	case <-ctx.Done():
		s.eventsRejected.Add(1)
		s.queryTimeouts.Add(1)
		http.Error(w, "query timeout", http.StatusGatewayTimeout)
		return
	case res := <-resCh:
		if res.err != nil {
			http.Error(w, "history read failed", http.StatusInternalServerError)
			return
		}
		rawEvents = res.raw
		truncated = res.truncated
	}

	if len(rawEvents) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"events":    []json.RawMessage{},
			"hours":     hours,
			"truncated": false,
			"count":     0,
			"pg_mode":   s.hub.PGMode(),
		})
		return
	}

	filtered := make([]json.RawMessage, 0, len(rawEvents))
	needFilter := nsFilter != "" || podFilter != "" || containerFilter != ""
	for _, raw := range rawEvents {
		if needFilter {
			var ev struct {
				Namespace string `json:"namespace"`
				Pod       string `json:"pod"`
				Container string `json:"container"`
			}
			if err := json.Unmarshal(raw, &ev); err != nil {
				continue
			}
			if nsFilter != "" && ev.Namespace != nsFilter {
				continue
			}
			if podFilter != "" && ev.Pod != podFilter {
				continue
			}
			if containerFilter != "" && ev.Container != containerFilter {
				continue
			}
		}
		filtered = append(filtered, json.RawMessage(raw))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"events":    filtered,
		"hours":     hours,
		"truncated": truncated,
		"count":     len(filtered),
		"pg_mode":   s.hub.PGMode(),
	})
}

func currentNamespace() string {
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		return "default"
	}
	return ns
}

func configuredComponents() [][4]string {
	defaults := defaultComponents()
	if v := os.Getenv("COMPONENTS"); v != "" {
		defaults = strings.Split(v, ",")
	}
	out := make([][4]string, 0, len(defaults))
	for _, spec := range defaults {
		parts := strings.SplitN(strings.TrimSpace(spec), "|", 4)
		if len(parts) != 4 {
			continue
		}
		out = append(out, [4]string{parts[0], parts[1], parts[2], parts[3]})
	}
	return out
}
