package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wolfee-watcher/pkg/httputil"
	"github.com/wolfee-watcher/pkg/mtls"
	"github.com/wolfee-watcher/tracee-bridge/internal/hub"
	"github.com/wolfee-watcher/tracee-bridge/internal/k8s"
	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
	"github.com/wolfee-watcher/tracee-bridge/internal/ratelimit"
)

func defaultComponents() []string {
	return []string{
		"tracee-bridge|Tracee Bridge|deployment|tracee-bridge",
		"kvisior-ui|UI and API|deployment|kvisior-ui",
		"scanner-agent|Scanner Agent|deployment|scanner-agent",
		"tracee-ebpf|Tracee eBPF|daemonset|tracee",
		"kafka|Kafka|statefulset|kafka",
		"postgres|PostgreSQL|statefulset|postgres",
		"sensor|Sensor|deployment|sensor",
		"sentry-audit|Sentry Audit|statefulset|sentry-audit",
		"sentry-audit-logtail|Audit Log Tail|daemonset|sentry-audit-logtail",
		"kvisior-audit-ingest|Audit Ingest|deployment|kvisior-audit-ingest",
		"kvisior-audit-processor|Audit Processor|deployment|kvisior-audit-processor",
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
	hostPID  int
	hostPPID int
	hostTID  int
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
	enrichByPID        atomic.Int64
	enrichMissing      atomic.Int64
	queryTimeouts      atomic.Int64
	startTime          time.Time
	ingestReqs         atomic.Int64
	ingestLatencyNanos atomic.Int64
	queryReqs          atomic.Int64
	queryLatencyNanos  atomic.Int64

	eventQueue    chan queueItem
	ingestWorkers int
	workerWG      sync.WaitGroup
	workerQuit    chan struct{}
	quitOnce      sync.Once
	traceeSrv     atomic.Pointer[http.Server]

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
		workerQuit:    make(chan struct{}),
		querySem:      make(chan struct{}, queryConc),
		queryLimiter:  ratelimit.New(max(10, queryPerMin/6), queryPerMin),
		queryTimeout:  time.Duration(queryTimeoutMS) * time.Millisecond,
		debugLogs:     envBool("TRACEE_BRIDGE_DEBUG_LOGS", false),
	}

	for i := 0; i < workers; i++ {
		s.workerWG.Add(1)
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
	defer s.workerWG.Done()
	for {
		select {
		case item, ok := <-s.eventQueue:
			if !ok {
				return
			}
			s.process(item)
		case <-s.workerQuit:
			return
		}
	}
}

func (s *Server) process(item queueItem) {
	s.enrich(item)
	ui := item.ev
	if ui.Namespace != "" && s.podCache.IsSystemNS(ui.Namespace) {
		return
	}
	s.hub.Broadcast(ui)
	s.eventsAccepted.Add(1)
}

func (s *Server) Shutdown(timeout time.Duration) {
	deadline := time.Now().Add(timeout)

	if srv := s.traceeSrv.Load(); srv != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), timeout)
		if err := srv.Shutdown(shutCtx); err != nil {
			slog.Warn("tracee_listener_shutdown_incomplete",
				"component", "tracee-bridge/server",
				"error", err)
		}
		cancel()
	}

	for len(s.eventQueue) > 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	remaining := len(s.eventQueue)
	s.quitOnce.Do(func() { close(s.workerQuit) })
	workersDone := make(chan struct{})
	go func() {
		s.workerWG.Wait()
		close(workersDone)
	}()
	select {
	case <-workersDone:
	case <-time.After(time.Until(deadline)):
		slog.Error("ingest_workers_drain_incomplete",
			"component", "tracee-bridge/server",
			"remaining", remaining,
			"timeout", timeout.String(),
			"impact", "in-flight events may not have reached kafka")
		return
	}

	if remaining > 0 {
		slog.Error("ingest_queue_drain_incomplete",
			"component", "tracee-bridge/server",
			"remaining", remaining,
			"timeout", timeout.String(),
			"impact", "events_lost_before_kafka")
		return
	}
	slog.Info("ingest_queue_drained",
		"component", "tracee-bridge/server",
		"accepted_total", s.eventsAccepted.Load())
}

func (s *Server) enrich(item queueItem) {
	ui := item.ev
	if item.nodeName != "" && ui.Node == "" {
		ui.Node = item.nodeName
	}

	if ui.Pod == "" || ui.Namespace == "" || ui.PodUID == "" || ui.PodIP == "" {
		s.podCache.Enrich(item.rawCtxID, &ui.Pod, &ui.Namespace, &ui.Node, &ui.PodUID, &ui.PodIP)
	}

	if ui.PodUID == "" {
		if info, ok := s.podCache.LookupPID(item.hostPID, item.hostTID, item.hostPPID); ok {
			s.podCache.Apply(info, &ui.Pod, &ui.Namespace, &ui.Node, &ui.PodUID, &ui.PodIP)
			s.enrichByPID.Add(1)
		}
	}

	if ui.PodUID != "" {
		s.podCache.Remember(item.rawCtxID, item.hostPID, k8s.PodInfo{
			PodName:   ui.Pod,
			Namespace: ui.Namespace,
			NodeName:  ui.Node,
			PodUID:    ui.PodUID,
			PodIP:     ui.PodIP,
		})
		if item.hostTID > 0 && item.hostTID != item.hostPID {
			s.podCache.Remember("", item.hostTID, k8s.PodInfo{
				PodName:   ui.Pod,
				Namespace: ui.Namespace,
				NodeName:  ui.Node,
				PodUID:    ui.PodUID,
				PodIP:     ui.PodIP,
			})
		}
		return
	}

	if ui.ContainerID != "" || ui.Pod != "" {
		s.enrichMissing.Add(1)
	}
}

func (s *Server) Run() error {
	traceMux := http.NewServeMux()
	traceMux.HandleFunc("/tracee/event", httputil.CORS(s.handleTracee))
	traceMux.HandleFunc("/health", httputil.CORS(s.handleHealth))

	traceeSrv := &http.Server{
		Addr:              ":8080",
		Handler:           traceMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	s.traceeSrv.Store(traceeSrv)

	go func() {
		slog.Info("tracee_listener_started",
			"component", "tracee-bridge/server",
			"addr", ":8080",
			"mtls", false)
		if err := traceeSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
