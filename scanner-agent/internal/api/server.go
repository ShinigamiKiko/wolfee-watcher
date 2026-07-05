package api

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wolfee-watcher/pkg/mtls"
	internal "github.com/wolfee-watcher/scanner-agent/internal"
	"github.com/wolfee-watcher/scanner-agent/internal/epss"
	"github.com/wolfee-watcher/scanner-agent/internal/grype"
	"github.com/wolfee-watcher/scanner-agent/internal/harbor"
	"github.com/wolfee-watcher/pkg/httputil"
	"github.com/wolfee-watcher/scanner-agent/internal/k8s"
	"github.com/wolfee-watcher/scanner-agent/internal/registry"
)

type Server struct {
	ctx       context.Context
	k8s       *k8s.Client
	scanner   *grype.Scanner
	enricher  *epss.Enricher
	inspector *registry.Inspector
	addr      string

	mu      sync.RWMutex
	results map[string]*internal.ScanResult

	histMu    sync.RWMutex
	histories map[string]*internal.ImageHistory

	subs   map[chan internal.ScanEvent]struct{}
	subsMu sync.Mutex

	scanMu       sync.Mutex
	scanning     bool
	scanActive   int
	scanQueue    []string
	scanCancel   context.CancelFunc
	scanDebugLog bool
	scanStarted  atomic.Int64
	scanDone     atomic.Int64
	scanFailed   atomic.Int64

	schedMu  sync.RWMutex
	schedule internal.ScanSchedule

	baselines DigestStore

	digestCursor int

	harborStore *harbor.Store
	kv          *kvClient
}

func (s *Server) ListHistoriesSnapshot() []internal.ImageHistory {
	s.histMu.RLock()
	defer s.histMu.RUnlock()
	out := make([]internal.ImageHistory, 0, len(s.histories))
	for _, h := range s.histories {
		out = append(out, *h)
	}
	return out
}

func (s *Server) ListClusterImages(ctx context.Context) ([]internal.ClusterImage, error) {
	return s.k8s.ListImages(ctx)
}

func New(ctx context.Context, k8sClient *k8s.Client, scanner *grype.Scanner, enricher *epss.Enricher, addr string, harborStore *harbor.Store) *Server {
	kv := newKVClient()
	s := &Server{
		ctx:          ctx,
		k8s:          k8sClient,
		scanner:      scanner,
		enricher:     enricher,
		inspector:    registry.New(),
		addr:         addr,
		results:      make(map[string]*internal.ScanResult),
		histories:    make(map[string]*internal.ImageHistory),
		subs:         make(map[chan internal.ScanEvent]struct{}),
		scanDebugLog: envBool("SCAN_DEBUG_LOGS", false),
		schedule: internal.ScanSchedule{
			Enabled:   false,
			Frequency: internal.FreqDaily,
			TimeOfDay: "02:00",
			DayOfWeek: 1,
		},
		baselines:   newDigestStore(kv),
		harborStore: harborStore,
		kv:          kv,
	}
	s.loadSnapshots()
	s.applyHarborCreds()
	go s.scheduleLoop()
	go s.historyLoop()
	go s.digestWatchLoop()
	go s.harborCredsLoop(ctx)
	return s
}

func (s *Server) applyHarborCreds() {
	if s.harborStore == nil {
		return
	}
	cfg := s.harborStore.Config()
	if cfg == nil {
		return
	}
	s.scanner.SetHarborCreds(cfg.URL, cfg.Username, cfg.Token)
	s.inspector.InjectCreds(cfg.URL, cfg.Username, cfg.Token)
}

func (s *Server) harborCredsLoop(ctx context.Context) {
	t := time.NewTicker(35 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.applyHarborCreds()
		}
	}
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", httputil.CORS(s.handleHealth))
	mux.HandleFunc("/images", httputil.CORS(s.handleImages))
	mux.HandleFunc("/results", httputil.CORS(s.handleResults))
	mux.HandleFunc("/scan", httputil.CORS(s.handleScan))
	mux.HandleFunc("/scan/stop", httputil.CORS(s.handleScanStop))
	mux.HandleFunc("/stream", httputil.CORS(s.handleStream))
	mux.HandleFunc("/schedule", httputil.CORS(s.handleSchedule))
	mux.HandleFunc("/histories", httputil.CORS(s.handleHistories))
	s.registerBaselineRoutes(mux)
	slog.Info("scanner_agent_listener_started",
		"component", "scanner-agent/server",
		"addr", s.addr,
		"scan_debug_logs", s.scanDebugLog,
		"scan_workers", scanWorkers(),
		"scan_queue_limit", scanQueueLimit())

	return mtls.ListenAuto(s.ctx, s.addr,
		mtls.RequireServiceExcept(mux, []mtls.ServiceType{mtls.Kvisior}, "/health"),
		mtls.ScannerAgent, true)
}
