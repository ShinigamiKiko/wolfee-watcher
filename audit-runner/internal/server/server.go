package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/wolfee-watcher/audit-runner/internal/enricher"
	"github.com/wolfee-watcher/pkg/httputil"
	"github.com/wolfee-watcher/audit-runner/internal/jobs"
	"github.com/wolfee-watcher/audit-runner/internal/kv"
	"github.com/wolfee-watcher/audit-runner/internal/parser"
	"github.com/wolfee-watcher/audit-runner/internal/store"
	"github.com/wolfee-watcher/pkg/mtls"
)

type Server struct {
	ctx           context.Context
	addr          string
	store         *store.Store
	runner        *jobs.Runner
	kv            *kv.Client
	benchRunning  int32
	hunterRunning int32
}

func New(ctx context.Context, addr string, st *store.Store, runner *jobs.Runner, kvClient *kv.Client) *Server {
	return &Server{ctx: ctx, addr: addr, store: st, runner: runner, kv: kvClient}
}

func (s *Server) persistRun(tool, runID string, res store.ToolResult) {
	if s.kv == nil {
		return
	}
	s.kv.PushAuditRun(kv.AuditRun{
		Tool:      tool,
		RunID:     runID,
		Status:    string(res.Status),
		StartedAt: res.StartedAt,
		DoneAt:    res.DoneAt,
		Parsed:    res.Parsed,
		Error:     res.Error,
	})
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", httputil.CORS(s.handleHealth))
	mux.HandleFunc("/api/audit/run", httputil.CORS(s.handleRunBoth))
	mux.HandleFunc("/api/audit/run/bench", httputil.CORS(s.handleRunBench))
	mux.HandleFunc("/api/audit/run/hunter", httputil.CORS(s.handleRunHunter))
	mux.HandleFunc("/api/audit/current", httputil.CORS(s.handleCurrent))
	mux.HandleFunc("/api/audit/history", httputil.CORS(s.handleHistory))
	log.Printf("[server] listening on %s", s.addr)
	return mtls.ListenAuto(s.ctx, s.addr, mtls.SecureMuxExcept(mux, "/health"), mtls.AuditRunner, true)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "audit-runner"}); err != nil {
		log.Printf("[server] encode response: %v", err)
	}
}

func (s *Server) handleRunBench(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !atomic.CompareAndSwapInt32(&s.benchRunning, 0, 1) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "bench_already_running"}); err != nil {
			log.Printf("[server] encode response: %v", err)
		}
		return
	}
	runID := fmt.Sprintf("b%d", time.Now().Unix())
	s.store.Begin(runID, true, false)
	go func() {
		defer atomic.StoreInt32(&s.benchRunning, 0)
		s.runBench(runID)
		s.store.Finish(runID)
	}()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "started", "run_id": runID, "tool": "bench"}); err != nil {
		log.Printf("[server] encode response: %v", err)
	}
}

func (s *Server) handleRunHunter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !atomic.CompareAndSwapInt32(&s.hunterRunning, 0, 1) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "hunter_already_running"}); err != nil {
			log.Printf("[server] encode response: %v", err)
		}
		return
	}
	runID := fmt.Sprintf("h%d", time.Now().Unix())
	s.store.Begin(runID, false, true)
	go func() {
		defer atomic.StoreInt32(&s.hunterRunning, 0)
		s.runHunter(runID)
		s.store.Finish(runID)
	}()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "started", "run_id": runID, "tool": "hunter"}); err != nil {
		log.Printf("[server] encode response: %v", err)
	}
}

func (s *Server) handleRunBoth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	go func() {
		if atomic.CompareAndSwapInt32(&s.benchRunning, 0, 1) {
			runID := fmt.Sprintf("b%d", time.Now().Unix())
			s.store.Begin(runID, true, false)
			defer atomic.StoreInt32(&s.benchRunning, 0)
			s.runBench(runID)
			s.store.Finish(runID)
		}
	}()
	go func() {
		if atomic.CompareAndSwapInt32(&s.hunterRunning, 0, 1) {
			runID := fmt.Sprintf("h%d", time.Now().Unix())
			s.store.Begin(runID, false, true)
			defer atomic.StoreInt32(&s.hunterRunning, 0)
			s.runHunter(runID)
			s.store.Finish(runID)
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "started"}); err != nil {
		log.Printf("[server] encode response: %v", err)
	}
}

func (s *Server) handleCurrent(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	current := s.store.Current()
	if current == nil {
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "no_runs_yet"}); err != nil {
			log.Printf("[server] encode response: %v", err)
		}
		return
	}
	if err := json.NewEncoder(w).Encode(current); err != nil {
		log.Printf("[server] encode response: %v", err)
	}
}

func (s *Server) handleHistory(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.store.History()); err != nil {
		log.Printf("[server] encode response: %v", err)
	}
}

func (s *Server) runBench(runID string) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), jobs.JobTimeout+30*time.Second)
	defer cancel()

	res := store.ToolResult{StartedAt: started, DoneAt: time.Now()}
	raw, err := s.runner.RunBench(ctx, runID)
	switch {
	case err != nil:
		log.Printf("[runner] bench error: %v", err)
		res.Status, res.Error = store.StatusError, err.Error()
	default:
		if parsed := parser.ParseBench(raw); parsed == nil {
			log.Printf("[runner] bench: failed to parse output (len=%d)", len(raw))
			res.Status, res.Error = store.StatusError, "failed to parse kube-bench JSON output"
		} else {
			log.Printf("[runner] bench done: %d controls pass=%d fail=%d warn=%d", len(parsed.Controls), parsed.Totals.Pass, parsed.Totals.Fail, parsed.Totals.Warn)
			res.Status, res.Parsed = store.StatusDone, parsed
		}
	}
	res.DoneAt = time.Now()
	s.store.UpdateBench(runID, res)
	s.persistRun("bench", runID, res)
}

func (s *Server) runHunter(runID string) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), jobs.JobTimeout+30*time.Second)
	defer cancel()

	raw, err := s.runner.RunHunter(ctx, runID)
	if err != nil {
		log.Printf("[runner] hunter error: %v", err)
		res := store.ToolResult{Status: store.StatusError, Error: err.Error(), StartedAt: started, DoneAt: time.Now()}
		s.store.UpdateHunter(runID, res)
		s.persistRun("hunter", runID, res)
		return
	}
	parsed := parser.ParseHunter(raw)
	log.Printf("[runner] hunter raw len=%d", len(raw))
	if len(raw) > 0 {
		preview := raw
		if len(preview) > 1000 {
			preview = preview[:1000]
		}
		log.Printf("[runner] hunter raw:\n%s", preview)
	} else {
		log.Printf("[runner] hunter raw is EMPTY - pod produced no output")
	}
	log.Printf("[runner] hunter parsed: %d nodes, %d services, %d vulns",
		len(parsed.Nodes), len(parsed.Services), len(parsed.Vulnerabilities))

	if len(parsed.Vulnerabilities) > 0 {
		log.Printf("[runner] enriching %d vulns from avd.aquasec.com…", len(parsed.Vulnerabilities))
		enricher.EnrichReport(parsed)
		log.Printf("[runner] enrichment done")
	}

	res := store.ToolResult{Status: store.StatusDone, Parsed: parsed, StartedAt: started, DoneAt: time.Now()}
	s.store.UpdateHunter(runID, res)
	s.persistRun("hunter", runID, res)
}
