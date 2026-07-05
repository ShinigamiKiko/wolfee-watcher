package server

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wolfee-watcher/anomaly-detector/internal/baseline"
	"github.com/wolfee-watcher/anomaly-detector/internal/broadcast"
	"github.com/wolfee-watcher/pkg/httputil"
	"github.com/wolfee-watcher/anomaly-detector/internal/integrations"
	"github.com/wolfee-watcher/anomaly-detector/internal/recon"
	"github.com/wolfee-watcher/pkg/mtls"
)

type statsProvider interface {
	Stats() (processed, anomalies int64)
}

type Server struct {
	addr       string
	ctx        context.Context
	pool       *pgxpool.Pool
	base       *baseline.Store
	cons       statsProvider
	recon      *recon.Detector
	bcast      *broadcast.Hub
	integ      *integrations.Store
	mgr        *integrations.Manager
	started    time.Time
	reqTotal   atomic.Int64
	reqErrors  atomic.Int64
	reqLatency atomic.Int64
	debugLogs  bool
}

func New(ctx context.Context, addr string, pool *pgxpool.Pool, base *baseline.Store,
	cons statsProvider, rec *recon.Detector, bcast *broadcast.Hub,
	integ *integrations.Store, mgr *integrations.Manager) *Server {
	return &Server{
		addr:      addr,
		ctx:       ctx,
		pool:      pool,
		base:      base,
		cons:      cons,
		recon:     rec,
		bcast:     bcast,
		integ:     integ,
		mgr:       mgr,
		started:   time.Now(),
		debugLogs: envBool("ANOMALY_DEBUG_LOGS", false),
	}
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	log.Printf("[server] listening on %s", s.addr)

	handler := mtls.RequireServiceExcept(limitBody(s.logRequests(mux)), []mtls.ServiceType{mtls.Kvisior}, "/health")
	return mtls.ListenAuto(s.ctx, s.addr, handler, mtls.AnomalyDetector, true)
}

const maxRequestBody = 1 << 20

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", httputil.CORS(s.handleHealth))
	mux.HandleFunc("/api/anomalies", httputil.CORS(s.handleAnomalies))
	mux.HandleFunc("/api/anomalies/delete", httputil.CORS(s.handleAnomalyDelete))
	mux.HandleFunc("/api/anomalies/ingest", httputil.CORS(s.handleAnomalyIngest))
	mux.HandleFunc("/api/anomalies/silent", httputil.CORS(s.handleAnomaliesSilent))
	mux.HandleFunc("/api/anomalies/silence", httputil.CORS(s.handleAnomalySilence))
	mux.HandleFunc("/api/anomalies/unsilence", httputil.CORS(s.handleAnomalyUnsilence))
	mux.HandleFunc("/api/silents", httputil.CORS(s.handleSilents))
	mux.HandleFunc("/api/stats", httputil.CORS(s.handleStats))
	mux.HandleFunc("/api/baselines", httputil.CORS(s.handleBaselines))
	mux.HandleFunc("/api/baselines/lock", httputil.CORS(s.handleLock))
	mux.HandleFunc("/api/network-graph", httputil.CORS(s.handleNetworkGraph))
	mux.HandleFunc("/api/events/stream", s.handleSSE)
	mux.HandleFunc("/api/integrations", httputil.CORS(s.handleIntegrations))
	mux.HandleFunc("/api/integrations/", httputil.CORS(s.handleIntegrationItem))
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		dur := time.Since(start)
		s.reqTotal.Add(1)
		s.reqLatency.Add(dur.Nanoseconds())
		if rw.status >= 400 {
			s.reqErrors.Add(1)
		}
		if s.debugLogs || rw.status >= 500 {
			log.Printf("[server] %s %s → %d (%s)", r.Method, r.URL.Path, rw.status, dur.Round(time.Millisecond))
		}
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
