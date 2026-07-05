package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/wolfee-watcher/anomaly-detector/internal/baseline"
)

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":   "ok",
		"service":  "anomaly-detector",
		"uptime":   time.Since(s.started).Round(time.Second).String(),
		"hostname": func() string { h, _ := os.Hostname(); return h }(),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	processed, anomalies := s.cons.Stats()
	deps, flows := s.base.Stats()
	reqTotal := s.reqTotal.Load()
	reqAvgMs := 0.0
	if reqTotal > 0 {
		reqAvgMs = float64(s.reqLatency.Load()) / float64(reqTotal) / float64(time.Millisecond)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"processed":            processed,
		"anomalies":            anomalies,
		"baseline_deployments": deps,
		"baseline_flows":       flows,
		"baseline_states":      s.base.StateMap(),
		"http_requests_total":  reqTotal,
		"http_requests_errors": s.reqErrors.Load(),
		"http_request_avg_ms":  reqAvgMs,
		"uptime_sec":           int64(time.Since(s.started).Seconds()),
	})
}

func (s *Server) handleBaselines(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	deps, flows := s.base.Stats()
	json.NewEncoder(w).Encode(map[string]any{
		"deployments": deps,
		"flows":       flows,
		"states":      s.base.StateMap(),
	})
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	ns := r.URL.Query().Get("ns")
	dep := r.URL.Query().Get("dep")
	if ns == "" || dep == "" {
		http.Error(w, "ns and dep required", http.StatusBadRequest)
		return
	}
	s.base.LockBaseline(ns, dep)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"locked": ns + "/" + dep})
}

func (s *Server) handleNetworkGraph(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	nodes, edges := s.base.AllFlows()
	if nodes == nil {
		nodes = []string{}
	}
	if edges == nil {
		edges = []baseline.GraphEdge{}
	}
	json.NewEncoder(w).Encode(map[string]any{
		"nodes":     nodes,
		"edges":     edges,
		"fetchedAt": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch := s.bcast.Subscribe()
	defer s.bcast.Unsubscribe(ch)
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}
