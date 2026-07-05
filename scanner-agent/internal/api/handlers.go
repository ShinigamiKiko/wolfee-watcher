package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	n := len(s.results)
	s.mu.RUnlock()

	s.scanMu.Lock()
	scanning := s.scanning
	queue := len(s.scanQueue)
	s.scanMu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	cluster := s.k8s.ClusterInfo(ctx)

	s.schedMu.RLock()
	sched := s.schedule
	s.schedMu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"scanned":     n,
		"scanning":    scanning,
		"queue":       queue,
		"clusterName": cluster.Name,
		"nodeCount":   cluster.NodeCount,
		"k8sVersion":  cluster.K8sVersion,
		"schedule":    sched,
	})
}

func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	imgs, err := s.k8s.ListImages(ctx)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(internal.ImagesResponse{Images: imgs, Total: len(imgs)})
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	out := make([]internal.ScanResult, 0, len(s.results))
	agg := internal.CVESummary{}
	for _, res := range s.results {
		out = append(out, *res)
		agg.Critical += res.Summary.Critical
		agg.High += res.Summary.High
		agg.Medium += res.Summary.Medium
		agg.Low += res.Summary.Low
		agg.Unknown += res.Summary.Unknown
		agg.Total += res.Summary.Total
		agg.Fixable += res.Summary.Fixable
		agg.InKEV += res.Summary.InKEV
		agg.HasPoC += res.Summary.HasPoC
	}
	s.mu.RUnlock()

	json.NewEncoder(w).Encode(internal.ResultsResponse{Results: out, Total: len(out), Summary: agg})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Images []string `json:"images"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil && err != io.EOF {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	refs := body.Images
	if len(refs) == 0 {
		refs = s.collectClusterRefs(r.Context(), w)
		if refs == nil {
			return
		}
	}

	if len(refs) == 0 {
		log.Printf("[scan] no images found in cluster")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"queued":  0,
			"images":  []string{},
			"message": "No running images found in cluster. Are pods running?",
		})
		return
	}

	queued := s.enqueueScan(refs)
	log.Printf("[scan] queued %d/%d images", queued, len(refs))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"queued":    queued,
		"requested": len(refs),
		"images":    refs,
	})
}

func (s *Server) collectClusterRefs(ctx context.Context, w http.ResponseWriter) []string {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	imgs, err := s.k8s.ListImages(reqCtx)
	if err != nil {
		log.Printf("[scan] k8s ListImages error: %v", err)

		s.mu.RLock()
		var fallback []string
		for ref := range s.results {
			if !hasPrefix(ref, "sha256:") {
				fallback = append(fallback, ref)
			}
		}
		s.mu.RUnlock()
		if len(fallback) == 0 {
			http.Error(w, fmt.Sprintf(`{"error":"k8s unavailable: %s"}`, err.Error()), 503)
			return nil
		}
		log.Printf("[scan] k8s error — rescanning %d previously known images", len(fallback))
		return fallback
	}

	log.Printf("[scan] k8s returned %d images", len(imgs))
	var refs []string
	for _, img := range imgs {
		ref := img.Ref
		if ref == "" {
			ref = img.Name
			if img.Tag != "" && img.Tag != "latest" {
				ref += ":" + img.Tag
			}
		}
		if ref == "" || hasPrefix(ref, "sha256:") || isBareSHA(ref) {
			continue
		}
		if hasPrefix(ref, "localhost/") || hasPrefix(ref, "127.0.0.1") {
			log.Printf("[scan] skipping local image: %s", ref)
			continue
		}
		refs = append(refs, ref)
	}
	return refs
}

func (s *Server) handleSchedule(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		return
	case http.MethodGet:
		s.schedMu.RLock()
		sched := s.schedule
		s.schedMu.RUnlock()
		json.NewEncoder(w).Encode(sched)
	case http.MethodPut:
		var req internal.ScanSchedule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, 400)
			return
		}
		if req.TimeOfDay != "" {
			if _, err := time.Parse("15:04", req.TimeOfDay); err != nil {
				http.Error(w, `{"error":"timeOfDay must be HH:MM"}`, 400)
				return
			}
		}
		if req.Frequency == "" {
			req.Frequency = internal.FreqDisabled
		}
		s.schedMu.Lock()
		s.schedule = req
		s.schedule.NextRun = computeNextRun(req)
		s.schedMu.Unlock()
		s.snapshotSchedule()
		log.Printf("[schedule] updated: enabled=%v freq=%s time=%s", req.Enabled, req.Frequency, req.TimeOfDay)
		s.schedMu.RLock()
		json.NewEncoder(w).Encode(s.schedule)
		s.schedMu.RUnlock()
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan internal.ScanEvent, 64)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	defer func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		s.subsMu.Unlock()
		close(ch)
	}()

	s.mu.RLock()
	for _, res := range s.results {
		b, _ := json.Marshal(internal.ScanEvent{Type: "result", Image: res.Image, Result: res})
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	s.mu.RUnlock()
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", b)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleHistories(w http.ResponseWriter, r *http.Request) {
	s.histMu.RLock()
	out := make([]internal.ImageHistory, 0, len(s.histories))
	for _, h := range s.histories {
		out = append(out, *h)
	}
	s.histMu.RUnlock()
	json.NewEncoder(w).Encode(internal.HistoriesResponse{Histories: out, Total: len(out)})
}
