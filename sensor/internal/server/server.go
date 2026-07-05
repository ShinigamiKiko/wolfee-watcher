package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/wolfee-watcher/pkg/mtls"
	"github.com/wolfee-watcher/sensor/internal/collector"
	"github.com/wolfee-watcher/pkg/httputil"
	"github.com/wolfee-watcher/sensor/internal/logstore"
)

type Server struct {
	addr       string
	ctx        context.Context
	client     kubernetes.Interface
	mu         sync.RWMutex
	snapGzip   []byte
	snapETag   string
	snapStruct *collector.Snapshot
	podNode    map[string]string
	podCount   int
	ls         *logstore.Store
	httpClient *http.Client
	reqTotal   atomic.Int64
	reqErrors  atomic.Int64
	reqLatency atomic.Int64
	debugLogs  bool
	started    time.Time
}

func (s *Server) GetSnapshot() *collector.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapStruct
}

func New(ctx context.Context, addr string, client kubernetes.Interface, ls *logstore.Store, httpClient *http.Client) *Server {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Server{
		addr:       addr,
		ctx:        ctx,
		client:     client,
		ls:         ls,
		httpClient: httpClient,
		debugLogs:  envBool("SENSOR_DEBUG_LOGS", false),
		started:    time.Now(),
	}
}

func (s *Server) Run() error {
	go s.runSnapshotSyncLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", httputil.CORS(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "service": "sensor"})
	}))
	mux.HandleFunc("/api/snapshot", httputil.CORS(s.handleSnapshot))
	mux.HandleFunc("/api/pods/", httputil.CORS(s.handlePodLogs))
	mux.HandleFunc("/api/forensic/watch/", httputil.CORS(func(w http.ResponseWriter, r *http.Request) { s.handleForensicWatch(w, r) }))
	mux.HandleFunc("/api/forensic/diff/", httputil.CORS(func(w http.ResponseWriter, r *http.Request) { s.handleForensicDiff(w, r) }))
	mux.HandleFunc("/api/forensic/tar/", httputil.CORS(func(w http.ResponseWriter, r *http.Request) { s.handleForensicTar(w, r) }))
	mux.HandleFunc("/api/nodes/", httputil.CORS(s.handleNodeRoutes))
	mux.HandleFunc("/stats", httputil.CORS(s.handleStats))

	logSensorRoutes(s.addr)
	go s.runHealthServer()
	return mtls.ListenAuto(s.ctx, s.addr, mtls.SecureMuxExcept(s.logRequests(mux), "/health"), mtls.Sensor, true)
}

func (s *Server) runSnapshotSyncLoop() {
	ticker := time.NewTicker(90 * time.Second)
	defer ticker.Stop()
	s.syncPodNodeFromPG()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.syncPodNodeFromPG()
		}
	}
}

func logSensorRoutes(addr string) {
	log.Printf("[sensor] listening on %s", addr)
	log.Printf("[sensor]   snapshot      : GET /api/snapshot")
	log.Printf("[sensor]   pod logs      : GET /api/pods/{ns}/{name}/logs")
	log.Printf("[sensor]   node events   : GET /api/nodes/{name}/events")
	log.Printf("[sensor]   forensic watch: POST /api/forensic/watch/{ns}/{pod}")
	log.Printf("[sensor]   forensic tar  : GET  /api/forensic/tar/{ns}/{pod}")
}

func (s *Server) runHealthServer() {
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", httputil.CORS(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"sensor"}`)
	}))
	log.Printf("[sensor] health probe listener on :8081 (plain HTTP)")
	if err := http.ListenAndServe(":8081", healthMux); err != nil {
		log.Printf("[sensor] health server error: %v", err)
	}
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		dur := time.Since(start)
		s.reqTotal.Add(1)
		s.reqLatency.Add(dur.Nanoseconds())
		if rw.status >= 400 {
			s.reqErrors.Add(1)
		}
		if s.debugLogs || rw.status >= 500 {
			log.Printf("[sensor] %s %s -> %d (%s)", r.Method, r.URL.Path, rw.status, dur.Round(time.Millisecond))
		}
	})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	total := s.reqTotal.Load()
	avgMs := 0.0
	if total > 0 {
		avgMs = float64(s.reqLatency.Load()) / float64(total) / float64(time.Millisecond)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service":              "sensor",
		"http_requests_total":  total,
		"http_requests_errors": s.reqErrors.Load(),
		"http_request_avg_ms":  avgMs,
		"uptime":               time.Since(s.started).Round(time.Second).String(),
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rw *statusRecorder) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}
