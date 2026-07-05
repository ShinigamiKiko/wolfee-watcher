package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

func scanWorkers() int {
	const defaultN = 2
	v := os.Getenv("SCAN_WORKERS")
	if v == "" {
		return defaultN
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		slog.Warn("invalid_int_env",
			"component", "scanner-agent/scan",
			"key", "SCAN_WORKERS",
			"value", v,
			"default", defaultN)
		return defaultN
	}
	return n
}

func scanQueueLimit() int {
	const defaultN = 5000
	v := os.Getenv("SCAN_QUEUE_LIMIT")
	if v == "" {
		return defaultN
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		slog.Warn("invalid_int_env",
			"component", "scanner-agent/scan",
			"key", "SCAN_QUEUE_LIMIT",
			"value", v,
			"default", defaultN)
		return defaultN
	}
	return n
}

func (s *Server) enqueueScan(refs []string) int {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()

	existing := make(map[string]bool, len(s.scanQueue))
	for _, r := range s.scanQueue {
		existing[r] = true
	}
	limit := scanQueueLimit()
	queued := 0
	dropped := 0
	for _, r := range refs {
		if existing[r] {
			continue
		}
		if limit > 0 && len(s.scanQueue) >= limit {
			dropped++
			continue
		}
		s.scanQueue = append(s.scanQueue, r)
		existing[r] = true
		queued++
	}
	if dropped > 0 {
		slog.Warn("scan_queue_full",
			"component", "scanner-agent/scan",
			"limit", limit,
			"dropped", dropped,
			"queued", queued,
			"queue_depth", len(s.scanQueue))
	}
	if len(s.scanQueue) > 0 && !s.scanning {
		n := scanWorkers()

		poolCtx, cancel := context.WithCancel(context.Background())
		s.scanCancel = cancel
		s.scanning = true
		s.scanActive = n
		slog.Info("scan_worker_pool_started",
			"component", "scanner-agent/scan",
			"workers", n,
			"queue_depth", len(s.scanQueue),
			"queue_limit", limit,
			"debug_logs", s.scanDebugLog)
		for i := 0; i < n; i++ {
			go s.runScanWorker(poolCtx, i)
		}
	}
	return queued
}

func (s *Server) stopScan() bool {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if !s.scanning || s.scanCancel == nil {
		return false
	}
	slog.Warn("scan_stop_requested",
		"component", "scanner-agent/scan",
		"pending", len(s.scanQueue),
		"action", "cancel_pool_drop_queue")
	s.scanCancel()

	s.scanQueue = nil
	return true
}

func (s *Server) runScanWorker(poolCtx context.Context, id int) {
	defer func() {
		s.scanMu.Lock()
		s.scanActive--
		last := s.scanActive == 0
		cancelled := poolCtx.Err() != nil
		if last {
			s.scanning = false
			s.scanCancel = nil
		}
		s.scanMu.Unlock()
		if last {
			if cancelled {
				s.broadcast(internal.ScanEvent{Type: "done", Message: "Scan stopped by user"})
				slog.Warn("scan_worker_pool_drained",
					"component", "scanner-agent/scan",
					"cancelled", true,
					"started_total", s.scanStarted.Load(),
					"done_total", s.scanDone.Load(),
					"failed_total", s.scanFailed.Load())
			} else {
				s.broadcast(internal.ScanEvent{Type: "done", Message: "All scans complete"})
				slog.Info("scan_worker_pool_drained",
					"component", "scanner-agent/scan",
					"cancelled", false,
					"started_total", s.scanStarted.Load(),
					"done_total", s.scanDone.Load(),
					"failed_total", s.scanFailed.Load())
			}
		}
	}()

	for {

		if poolCtx.Err() != nil {
			return
		}

		s.scanMu.Lock()
		if len(s.scanQueue) == 0 {
			s.scanMu.Unlock()
			return
		}
		ref := s.scanQueue[0]
		s.scanQueue = s.scanQueue[1:]
		s.scanMu.Unlock()

		s.processOne(poolCtx, id, ref)
	}
}

func (s *Server) processOne(poolCtx context.Context, workerID int, ref string) {
	s.scanStarted.Add(1)
	s.broadcast(internal.ScanEvent{Type: "start", Image: ref, Message: fmt.Sprintf("Scanning %s", ref)})
	if s.scanDebugLog {
		slog.Info("scan_started",
			"component", "scanner-agent/scan",
			"worker", workerID,
			"image", ref)
	}

	scanCtx, cancel := context.WithTimeout(poolCtx, 15*time.Minute)
	result, err := s.scanner.Scan(scanCtx, ref)
	cancel()

	if errors.Is(poolCtx.Err(), context.Canceled) {
		if s.scanDebugLog {
			slog.Info("scan_cancelled",
				"component", "scanner-agent/scan",
				"worker", workerID,
				"image", ref)
		}
		return
	}

	if err != nil {
		s.scanFailed.Add(1)
		slog.Error("scan_failed",
			"component", "scanner-agent/scan",
			"worker", workerID,
			"image", ref,
			"error", err)
		errResult := &internal.ScanResult{
			Image: ref, Name: ref, Status: internal.StatusError,
			Error: err.Error(), ScannedAt: time.Now(),
		}
		s.mu.Lock()
		s.results[ref] = errResult
		s.mu.Unlock()
		s.kv.PushResult(errResult)
		s.broadcast(internal.ScanEvent{Type: "error", Image: ref, Message: err.Error(), Result: errResult})
		return
	}

	if s.scanDebugLog {
		slog.Info("scan_enrich_started",
			"component", "scanner-agent/scan",
			"worker", workerID,
			"image", ref,
			"cves", len(result.CVEs))
	}
	enrichCtx, enrichCancel := context.WithTimeout(poolCtx, 5*time.Minute)
	result.CVEs = s.enricher.Enrich(enrichCtx, result.CVEs)
	enrichCancel()

	if errors.Is(poolCtx.Err(), context.Canceled) {
		if s.scanDebugLog {
			slog.Info("scan_cancelled_during_enrich",
				"component", "scanner-agent/scan",
				"worker", workerID,
				"image", ref)
		}
		return
	}

	result.Summary = buildSummary(result.CVEs)
	result.Status = internal.StatusDone

	s.mu.Lock()
	s.results[ref] = result
	s.mu.Unlock()
	s.kv.PushResult(result)

	s.scanDone.Add(1)
	if s.scanDebugLog {
		slog.Info("scan_completed",
			"component", "scanner-agent/scan",
			"worker", workerID,
			"image", ref,
			"total_cves", result.Summary.Total,
			"critical", result.Summary.Critical,
			"high", result.Summary.High,
			"kev", result.Summary.InKEV,
			"poc", result.Summary.HasPoC)
	}
	s.broadcast(internal.ScanEvent{Type: "result", Image: ref, Result: result})
}

func buildSummary(cves []internal.CVE) internal.CVESummary {
	s := internal.CVESummary{Total: len(cves)}
	for _, c := range cves {
		switch c.Severity {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		case "LOW":
			s.Low++
		default:
			s.Unknown++
		}
		if c.HasFix {
			s.Fixable++
		}
		if c.InKEV {
			s.InKEV++
		}
		if len(c.PoCs) > 0 {
			s.HasPoC++
		}
	}
	return s
}

func (s *Server) broadcast(ev internal.ScanEvent) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		slog.Warn("invalid_bool_env",
			"component", "scanner-agent/scan",
			"key", key,
			"value", v,
			"default", def)
		return def
	}
	return b
}
