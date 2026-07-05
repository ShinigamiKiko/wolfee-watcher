package server

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/wolfee-watcher/pkg/mtls"
	"github.com/wolfee-watcher/pkg/httputil"
	"github.com/wolfee-watcher/tracee-bridge/internal/hub"
	"github.com/wolfee-watcher/tracee-bridge/internal/k8s"
	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
	"github.com/wolfee-watcher/tracee-bridge/internal/ratelimit"
)

func defaultComponents() []string {
	return []string{
		"tracee-bridge|Tracee Bridge|deployment|tracee-bridge",
		"scanner-agent|Scanner Agent|deployment|scanner-agent",
		"tracee-ebpf|Tracee eBPF|daemonset|tracee",
		"kafka|Kafka|statefulset|kafka",
		"postgres|PostgreSQL|statefulset|postgres",
		"sensor|Sensor|deployment|sensor",
		"sentry-audit|Sentry Audit|deployment|sentry-audit",
		"anomaly-detector|Anomaly Detector|deployment|anomaly-detector",
		"honey-operator|Honey Operator|deployment|honey-operator",
		"audit-runner|Audit Runner|deployment|audit-runner",
		"forensic-watcher|Forensic Watcher|daemonset|forensic-watcher",
		"cert-server|Cert Server|deployment|cert-server",
	}
}

var histBoundsMs = []int64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000}

type queueItem struct {
	ev       *mapper.UIEvent
	nodeName string
	rawCtxID string
}

type Server struct {
	ctx                context.Context
	hub                *hub.Hub
	addr               string
	podCache           *k8s.PodCache
	eventsTotal        atomic.Int64
	eventsAccepted     atomic.Int64
	eventsRejected     atomic.Int64
	eventsRateLimited  atomic.Int64
	eventsBusy         atomic.Int64
	eventsDropped      atomic.Int64
	eventsOverflow     atomic.Int64
	queryTimeouts      atomic.Int64
	startTime          time.Time
	ingestReqs         atomic.Int64
	ingestLatencyNanos atomic.Int64
	queryReqs          atomic.Int64
	queryLatencyNanos  atomic.Int64

	eventQueue    chan queueItem
	ingestWorkers int

	querySem     chan struct{}
	queryLimiter *ratelimit.Limiter
	queryTimeout time.Duration
	debugLogs    bool

	ingestHist [11]atomic.Int64
}

func New(ctx context.Context, h *hub.Hub, addr string) *Server {
	queryConc := envInt("TRACEE_QUERY_MAX_CONCURRENCY", 4)
	queryPerMin := envInt("TRACEE_QUERY_RATE_PER_MIN", 240)
	queryTimeoutMS := envInt("TRACEE_QUERY_TIMEOUT_MS", 4000)

	queueSize := envInt("TRACEE_INGEST_QUEUE_SIZE", 50000)
	workers := envInt("TRACEE_INGEST_WORKERS", 8)

	s := &Server{
		ctx:           ctx,
		hub:           h,
		addr:          addr,
		podCache:      k8s.New(ctx),
		startTime:     time.Now(),
		eventQueue:    make(chan queueItem, queueSize),
		ingestWorkers: workers,
		querySem:      make(chan struct{}, queryConc),
		queryLimiter:  ratelimit.New(max(10, queryPerMin/6), queryPerMin),
		queryTimeout:  time.Duration(queryTimeoutMS) * time.Millisecond,
		debugLogs:     envBool("TRACEE_BRIDGE_DEBUG_LOGS", false),
	}

	for i := 0; i < workers; i++ {
		go s.ingestWorker()
	}

	slog.Info("ingest_pipeline_started",
		"component", "tracee-bridge/server",
		"queue_capacity", queueSize,
		"workers", workers,
		"query_max_concurrency", queryConc,
		"query_rate_per_min", queryPerMin,
		"query_timeout_ms", queryTimeoutMS)

	return s
}

func (s *Server) ingestWorker() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case item, ok := <-s.eventQueue:
			if !ok {
				return
			}
			ui := item.ev
			if item.nodeName != "" && ui.Node == "" {
				ui.Node = item.nodeName
			}
			if ui.Pod == "" || ui.Namespace == "" {
				s.podCache.Enrich(item.rawCtxID, &ui.Pod, &ui.Namespace, &ui.Node)
			}
			if ui.Namespace != "" && s.podCache.IsSystemNS(ui.Namespace) {
				continue
			}
			s.hub.Broadcast(ui)
			s.eventsAccepted.Add(1)
		}
	}
}

func (s *Server) Run() error {
	traceMux := http.NewServeMux()
	traceMux.HandleFunc("/tracee/event", httputil.CORS(s.handleTracee))
	traceMux.HandleFunc("/health", httputil.CORS(s.handleHealth))

	go func() {
		slog.Info("tracee_listener_started",
			"component", "tracee-bridge/server",
			"addr", ":8080",
			"mtls", false)
		srv := &http.Server{
			Addr:              ":8080",
			Handler:           traceMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("tracee_listener_failed",
				"component", "tracee-bridge/server",
				"addr", ":8080",
				"error", err)
		}
	}()

	apiMux := http.NewServeMux()

	apiMux.HandleFunc("/events", httputil.CORS(s.handleEventsList))
	apiMux.HandleFunc("/events/query", httputil.CORS(s.handleEventsQuery))
	apiMux.HandleFunc("/health", httputil.CORS(s.handleHealth))
	apiMux.HandleFunc("/stats", httputil.CORS(s.handleStats))
	apiMux.HandleFunc("/components", httputil.CORS(s.handleComponents))
	apiMux.HandleFunc("/k8s-metrics", httputil.CORS(s.handleK8sMetrics))
	apiMux.HandleFunc("/kafka-stats", httputil.CORS(s.handleKafkaStats))

	apiMux.HandleFunc("/alerts", httputil.CORS(s.handleAlerts))

	slog.Info("api_listener_started",
		"component", "tracee-bridge/server",
		"addr", ":8081",
		"mtls", true)

	return mtls.ListenAuto(s.ctx, ":8081",
		mtls.RequireServiceExcept(apiMux, []mtls.ServiceType{mtls.Kvisior, mtls.AnomalyDetector}, "/health"),
		mtls.TraceeBridge, true)
}
