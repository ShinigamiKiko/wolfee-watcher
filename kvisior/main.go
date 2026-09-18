package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wolfee-watcher/kvisior/internal/accounts"
	"github.com/wolfee-watcher/kvisior/internal/apihandler"
	"github.com/wolfee-watcher/kvisior/internal/auth"
	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/collector"
	"github.com/wolfee-watcher/kvisior/internal/grpcserver"
	"github.com/wolfee-watcher/kvisior/internal/hub"
	kafkaconsumer "github.com/wolfee-watcher/kvisior/internal/kafka"
	"github.com/wolfee-watcher/kvisior/internal/podwatch"
	"github.com/wolfee-watcher/kvisior/internal/push"
	"github.com/wolfee-watcher/kvisior/internal/rules"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/kvisior/internal/uibus"
	"github.com/wolfee-watcher/kvisior/internal/watchring"
	alertspkg "github.com/wolfee-watcher/pkg/alerts"
	"github.com/wolfee-watcher/pkg/logging"
	"github.com/wolfee-watcher/pkg/mtls"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/credentials"
)

//go:embed all:dist
var uiFiles embed.FS

type backend struct {
	prefix  string
	host    string
	timeout time.Duration
}

type forensicSummaryEntry struct {
	events  []store.BinaryEventSummary
	expires time.Time
}

type forensicSummaryCache struct {
	mu      sync.RWMutex
	entries map[string]forensicSummaryEntry
	sf      singleflight.Group
}

func (c *forensicSummaryCache) lookup(cluster string) ([]store.BinaryEventSummary, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[cluster]
	if !ok || !time.Now().Before(e.expires) {
		return nil, false
	}
	return e.events, true
}

func (c *forensicSummaryCache) invalidate(cluster string) {
	c.mu.Lock()
	delete(c.entries, cluster)
	c.mu.Unlock()
}

func (c *forensicSummaryCache) get(ctx context.Context, sc *store.Scoped) ([]store.BinaryEventSummary, error) {
	if events, ok := c.lookup(sc.ID()); ok {
		return events, nil
	}
	result, err, _ := c.sf.Do("forensic-summary/"+sc.ID(), func() (interface{}, error) {
		if events, ok := c.lookup(sc.ID()); ok {
			return events, nil
		}
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		events, err := sc.QueryBinaryEventSummary(qctx)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		if c.entries == nil {
			c.entries = make(map[string]forensicSummaryEntry)
		}
		c.entries[sc.ID()] = forensicSummaryEntry{
			events:  events,
			expires: time.Now().Add(30 * time.Second),
		}
		c.mu.Unlock()
		return events, nil
	})
	if err != nil {
		return nil, err
	}
	return result.([]store.BinaryEventSummary), nil
}

func backends() []backend {
	return []backend{
		{"/api/", mtls.ServiceHost("tracee-bridge", 8081), 0},
		{"/scanner/", mtls.ServiceHost("scanner-agent", 9090), 10 * time.Minute},
		{"/sensor/", mtls.ServiceHost("sensor", 8080), 5 * time.Minute},
		{"/sentry/", mtls.ServiceHost("sentry-audit", 8080), 30 * time.Second},
		{"/anomaly/", mtls.ServiceHost("anomaly-detector", 8080), 0},
		{"/honey/", mtls.ServiceHost("honey-operator", 9095), 0},
		{"/audit/", mtls.ServiceHost("audit-runner", 8080), 2 * time.Minute},
	}
}

func main() {
	logging.Setup("kvisior")
	clusterctx.Init()
	addr := os.Getenv("KVISIOR_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scheme := "http"
	var baseTransport http.RoundTripper = http.DefaultTransport
	var grpcCreds credentials.TransportCredentials

	if os.Getenv("CERT_SERVER_ADDR") != "" {
		holder, err := mtls.NewCertHolder(ctx, mtls.Kvisior)
		if err != nil {
			log.Fatalf("[kvisior] cert-server: %v", err)
		}
		client, err := mtls.NewSecureClientFromHolder(holder)
		if err != nil {
			log.Fatalf("[kvisior] build mTLS client: %v", err)
		}
		baseTransport = client.Transport
		scheme = "https"

		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(holder.CA())
		grpcCreds = credentials.NewTLS(&tls.Config{
			GetCertificate: holder.GetCertificate,
			ClientAuth:     tls.RequireAndVerifyClientCert,
			ClientCAs:      caPool,
			MinVersion:     tls.VersionTLS13,
		})
		log.Printf("[kvisior] dynamic mTLS enabled via cert-server (https, rotation every 3h)")
	} else {
		certs, err := mtls.TryLoad()
		if err != nil {
			log.Fatalf("[kvisior] load mTLS certs: %v", err)
		}
		if certs != nil {
			secureClient, err := mtls.NewSecureClient(certs)
			if err != nil {
				log.Fatalf("[kvisior] build mTLS client: %v", err)
			}
			baseTransport = secureClient.Transport
			scheme = "https"

			tlsCfg, err := mtls.ServerConfig(certs)
			if err != nil {
				log.Fatalf("[kvisior] build gRPC TLS config: %v", err)
			}
			grpcCreds = credentials.NewTLS(tlsCfg)
			log.Printf("[kvisior] static mTLS enabled — presenting Wolfee-Watcher cert to all backends (https)")
		} else {
			log.Printf("[kvisior] no mTLS certs — plain HTTP to backends (dev mode)")
		}
	}

	mux := http.NewServeMux()

	anomalyBase := scheme + "://" + mtls.ServiceHost("anomaly-detector", 8080)
	if v := os.Getenv("KVISIOR_ANOMALY_BASE"); v != "" {
		anomalyBase = v
	}

	sensorBase := scheme + "://" + mtls.ServiceHost("sensor", 8080)
	if v := os.Getenv("KVISIOR_SENSOR_BASE"); v != "" {
		sensorBase = v
	}

	evHub := hub.New(5000)
	matcher := rules.New()
	auditMatcher := rules.NewAuditMatcher()
	mkBkCl := func() *http.Client { return &http.Client{Transport: baseTransport, Timeout: 10 * time.Second} }

	kafkaBrokers := os.Getenv("KAFKA_BROKERS")
	kafkaTopic := os.Getenv("KAFKA_TOPIC")
	if kafkaTopic == "" {
		kafkaTopic = "tracee-events"
	}
	var brokers []string
	if kafkaBrokers != "" {
		brokers = strings.Split(kafkaBrokers, ",")
	}

	uiBus := uibus.New(ctx, evHub, brokers)

	var (
		pgPool *pgxpool.Pool
		st     *store.Store
	)
	if pgDSN := os.Getenv("POSTGRES_DSN"); pgDSN != "" {
		var err error
		pgPool, err = pgxpool.New(ctx, pgDSN)
		if err != nil {
			log.Printf("[kvisior] postgres pool: %v — falling back to proxy mode", err)
		} else {
			initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			st, err = store.NewFromPool(initCtx, pgPool)
			cancel()
			if err != nil {
				log.Printf("[kvisior] postgres store: %v — falling back to proxy mode", err)
				pgPool.Close()
				pgPool = nil
			} else {
				defer pgPool.Close()
				log.Printf("[kvisior] PostgreSQL connected — serving /api/* directly from DB")
				regCtx, cancelReg := context.WithTimeout(ctx, 5*time.Second)
				if err := st.EnsureCluster(regCtx, clusterctx.Local()); err != nil {
					log.Printf("[kvisior] register local cluster %q: %v", clusterctx.Local(), err)
				}
				cancelReg()
				go st.RunRetention(ctx)

				go alertspkg.RunCleanup(ctx, pgPool)
				go alertspkg.RunWebhookDelivery(ctx, pgPool)
			}
		}
	} else {
		log.Printf("[kvisior] POSTGRES_DSN not set — /api/* proxied to tracee-bridge")
	}

	ctrlPool := pgPool
	if ctrlDSN := os.Getenv("POSTGRES_CONTROL_DSN"); ctrlDSN != "" {
		p, err := pgxpool.New(ctx, ctrlDSN)
		if err != nil {
			log.Printf("[kvisior] control-plane postgres pool: %v — falling back to the data pool", err)
		} else {
			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = p.Ping(pingCtx)
			cancel()
			if err != nil {
				log.Printf("[kvisior] control-plane postgres ping: %v — falling back to the data pool", err)
				p.Close()
			} else {
				defer p.Close()
				ctrlPool = p
				log.Printf("[kvisior] control-plane (accounts, sessions, tokens) on a separate pool")
			}
		}
	}

	secureCookie := os.Getenv("KVISIOR_SECURE_COOKIE") == "true"
	var authMgr *auth.Manager
	if ctrlPool != nil {
		authMgr = auth.New(accounts.NewStore(ctrlPool), secureCookie)
	} else {

		authMgr = auth.New(nil, secureCookie)
	}
	authMgr.StartSessionPurge(ctx)

	fed := newFederation(st)
	fed.register(ctx)
	authed := fed.requireAuth(authMgr)

	agg := collector.New(
		evHub,
		mkBkCl(), mkBkCl(),
		anomalyBase, sensorBase,
		auditMatcher, st,
	)
	go agg.Run(ctx)

	watchRing := watchring.New(ctx)
	podWatchMgr := podwatch.New(st.Cluster(clusterctx.Local()), watchRing)
	if st != nil {
		if err := podWatchMgr.Load(ctx); err != nil {
			log.Printf("[kvisior] podwatch load: %v", err)
		}
	}
	var policyConsumer *kafkaconsumer.Consumer
	if len(brokers) > 0 {

		kc, err := kafkaconsumer.New(brokers, kafkaTopic, uiBus, matcher, st, podWatchMgr)
		if err != nil {
			log.Printf("[kvisior] kafka consumer init: %v — Forensics live feed disabled", err)
		} else {
			policyConsumer = kc
			go kc.Run(ctx)

			go kafkaconsumer.RunLive(ctx, brokers, kafkaTopic, evHub, podWatchMgr, matcher)
			go kafkaconsumer.WarmWatchRing(ctx, brokers, kafkaTopic, podWatchMgr)
			log.Printf("[kvisior] kafka consumers started: brokers=%v topic=%s (processing group=kvisior-tracee + groupless live feed gated by active policies; binary-exec always streamed for Forensics)", brokers, kafkaTopic)
		}
	} else {
		log.Printf("[kvisior] KAFKA_BROKERS not set — Forensics live feed disabled")
	}

	grpcAddr := os.Getenv("KVISIOR_GRPC_ADDR")
	if grpcAddr == "" {
		grpcAddr = ":9091"
	}
	if _, err := grpcserver.Start(ctx, grpcAddr, grpcCreds, uiBus, evHub, matcher, auditMatcher, st); err != nil {
		log.Fatalf("[kvisior] grpc: %v", err)
	}

	pushH := push.New(uiBus, evHub, matcher, auditMatcher, st)
	pushWrap := pushSecretMiddleware(os.Getenv("INTERNAL_PUSH_SECRET"))
	mux.HandleFunc("/internal/push/events", pushWrap(pushH.HandleEvents))
	mux.HandleFunc("/internal/push/audit", pushWrap(pushH.HandleAuditEvents))
	mux.HandleFunc("/internal/push/sensor", pushWrap(pushH.HandleSensorSnapshot))
	mux.HandleFunc("/internal/push/anomaly", pushWrap(pushH.HandleAnomalyEvents))
	mux.HandleFunc("/internal/push/honeypot", pushWrap(pushH.HandleHoneypotEvents))
	mux.HandleFunc("/internal/push/scan", pushWrap(pushH.HandleScan))
	mux.HandleFunc("/internal/push/audit-run", pushWrap(pushH.HandleAuditRun))
	mux.HandleFunc("/internal/push/histories", pushWrap(pushH.HandleHistories))
	mux.HandleFunc("/internal/push/scanner-state", pushWrap(pushH.HandleScannerStatePush))
	mux.HandleFunc("/internal/pull/scanner-state", pushWrap(pushH.HandleScannerStatePull))
	mux.HandleFunc("/internal/push/forensic", pushWrap(pushH.HandleForensicEvents))
	mux.HandleFunc("/internal/push/forensic-watch", pushWrap(pushH.HandleForensicWatch))
	mux.HandleFunc("/internal/pull/forensic", pushWrap(pushH.HandleForensicDiff))
	mux.HandleFunc("/internal/pull/forensic-watches", pushWrap(pushH.HandleForensicWatchesPull))
	mux.HandleFunc("/internal/pull/alert-rules", pushWrap(pushH.HandleAlertRules))
	mux.HandleFunc("/internal/push/logs", pushWrap(pushH.HandleLogs))
	mux.HandleFunc("/internal/pull/logs", pushWrap(pushH.HandleLogsPull))
	mux.HandleFunc("/internal/pull/log-cursors", pushWrap(pushH.HandleLogCursors))
	mux.HandleFunc("/internal/push/snapshot-cache", pushWrap(pushH.HandleSnapshotCachePush))
	mux.HandleFunc("/internal/pull/snapshot-cache", pushWrap(pushH.HandleSnapshotCachePull))
	mux.HandleFunc("/internal/pull/integration", pushWrap(pushH.HandleIntegrationPull))
	log.Printf("[kvisior] push endpoints: /internal/push/{events,audit,sensor,anomaly,honeypot,scan,audit-run,histories,scanner-state,forensic,forensic-watch,logs,snapshot-cache}, /internal/pull/{scanner-state,forensic,alert-rules,logs,log-cursors,snapshot-cache} (secret=%v)", os.Getenv("INTERNAL_PUSH_SECRET") != "")

	appVersion := os.Getenv("APP_VERSION")
	if appVersion == "" {
		appVersion = "dev"
	}
	mux.Handle("/v1/version", authed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": appVersion})
	})))
	log.Printf("[kvisior] /v1/version → %s", appVersion)

	mux.Handle("/v1/stream", authed(fed.route(evHub)))
	log.Printf("[kvisior] /v1/stream → SSE hub (buf=5000)")

	if st != nil {
		var summaryCache forensicSummaryCache
		mux.Handle("/v1/binary-events", authed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			events, err := st.Cluster(clusterctx.ForRead(r)).QueryBinaryExecEvents(r.Context(), store.BinaryExecQuery{
				Namespace: r.URL.Query().Get("namespace"),
				Pod:       r.URL.Query().Get("pod"),
				PodUID:    r.URL.Query().Get("pod_uid"),
				Limit:     limit,
			})
			if err != nil {
				http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
				return
			}
			if events == nil {
				events = []json.RawMessage{}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"events": events, "total": len(events)})
		})))
		log.Printf("[kvisior] /v1/binary-events enabled (24h PostgreSQL history)")

		mux.Handle("/v1/forensic-summary", authed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			summary, err := summaryCache.get(r.Context(), st.Cluster(clusterctx.ForRead(r)))
			if err != nil {
				http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"events": summary})
		})))

		mux.Handle("/v1/forensic-events/clear", authed(mutationsRequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			ns, pod := r.URL.Query().Get("ns"), r.URL.Query().Get("pod")
			if ns == "" || pod == "" {
				http.Error(w, `{"error":"ns and pod required"}`, http.StatusBadRequest)
				return
			}
			deleted, err := st.Cluster(clusterctx.ForRead(r)).DeletePodEvents(r.Context(), ns, pod)
			if err != nil {
				http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
				return
			}
			summaryCache.invalidate(clusterctx.ForRead(r))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"runtime_deleted": deleted.Runtime,
				"anomaly_deleted": deleted.Anomaly,
			})
		}))))

		mux.Handle("/v1/forensic-events", authed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			ns, pod := r.URL.Query().Get("ns"), r.URL.Query().Get("pod")
			podUID := r.URL.Query().Get("pod_uid")
			containerID := r.URL.Query().Get("container_id")
			if ns == "" || pod == "" {
				http.Error(w, `{"error":"ns and pod required"}`, http.StatusBadRequest)
				return
			}
			selected, err := podWatchMgr.GetWatch(r.Context(), ns, pod)
			if err != nil {
				http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
				return
			}
			sinceID, _ := strconv.ParseInt(r.URL.Query().Get("since_id"), 10, 64)
			page, err := st.Cluster(clusterctx.ForRead(r)).QueryFilteredBinaryEvents(r.Context(), store.ForensicEventQuery{
				Namespace: ns, Pod: pod, PodUID: podUID, ContainerID: containerID,
				Syscalls: store.WatchedSyscalls(selected), SinceID: sinceID,
			})
			if err != nil {
				http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"events": page.Events, "next_since_id": page.NextID, "has_more": page.HasMore,
			})
		})))

		mux.Handle("/v1/forensic-watches", authed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			watches, err := st.Cluster(clusterctx.ForRead(r)).ListActiveForensicWatches(r.Context())
			if err != nil {
				http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"watches": watches})
		})))
	}

	mux.Handle("/v1/pod-watch", authed(mutationsRequireAdmin(fed.routeFunc(func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("ns")
		pod := r.URL.Query().Get("pod")
		if ns == "" || pod == "" {
			http.Error(w, `{"error":"ns and pod required"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			sc, err := podWatchMgr.GetWatch(r.Context(), ns, pod)
			if err != nil {
				sc = store.PodWatchSelection{}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"syscalls": sc.Syscalls, "lsm_hooks": sc.LSMHooks, "tracepoints": sc.Tracepoints,
			})
		case http.MethodPut:
			var body store.PodWatchSelection
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
				return
			}

			if len(body.Syscalls)+len(body.LSMHooks)+len(body.Tracepoints) > 13 {
				http.Error(w, `{"error":"max 13 watch events"}`, http.StatusBadRequest)
				return
			}
			if err := podWatchMgr.SetWatch(r.Context(), ns, pod, body); err != nil {
				http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			podWatchMgr.DeleteWatch(r.Context(), ns, pod)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))))

	mux.Handle("/v1/pod-syscall-events", authed(fed.routeFunc(func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("ns")
		pod := r.URL.Query().Get("pod")
		podUID := r.URL.Query().Get("pod_uid")
		containerID := r.URL.Query().Get("container_id")
		if ns == "" || pod == "" {
			http.Error(w, `{"error":"ns and pod required"}`, http.StatusBadRequest)
			return
		}
		evts := podWatchMgr.GetEvents(ns, pod, podUID, containerID)
		if evts == nil {
			evts = []json.RawMessage{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"events": evts})
	})))

	mux.Handle("/v1/honeypot-hidden", authed(mutationsRequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
			return
		}
		ns := r.URL.Query().Get("ns")
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			if ns == "" || name == "" {
				http.Error(w, `{"error":"ns and name required"}`, http.StatusBadRequest)
				return
			}
			ids, err := st.Cluster(clusterctx.ForRead(r)).HiddenHoneypotEvents(r.Context(), ns, name)
			if err != nil {
				http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
				return
			}
			if ids == nil {
				ids = []string{}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"ids": ids})
		case http.MethodPost:
			var body struct {
				NS   string `json:"ns"`
				Name string `json:"name"`
				ID   string `json:"id"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
				return
			}
			if body.NS == "" || body.Name == "" || body.ID == "" {
				http.Error(w, `{"error":"ns, name and id required"}`, http.StatusBadRequest)
				return
			}
			if err := st.Cluster(clusterctx.ForRead(r)).HideHoneypotEvent(r.Context(), body.NS, body.Name, body.ID); err != nil {
				http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))))

	mux.Handle("/v1/honeypot-events", authed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("ns")
		name := r.URL.Query().Get("name")
		if ns == "" || name == "" {
			http.Error(w, `{"error":"ns and name required"}`, http.StatusBadRequest)
			return
		}
		events, err := st.Cluster(clusterctx.ForRead(r)).ListHoneypotEvents(r.Context(), ns, name)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}
		if events == nil {
			events = []json.RawMessage{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"events": events, "total": len(events)})
	})))

	mux.Handle("/v1/violations", authed(mutationsRequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodDelete:
			fp := r.URL.Query().Get("fp")
			if fp == "" {
				http.Error(w, `{"error":"fp required"}`, http.StatusBadRequest)
				return
			}

			if err := st.Cluster(clusterctx.ForRead(r)).SetViolationState(r.Context(), fp, store.StateDismissed, store.StateDismissedDuration); err != nil {
				http.Error(w, `{"error":"delete failed"}`, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodPost:
			fp := r.URL.Query().Get("fp")
			state := strings.ToUpper(r.URL.Query().Get("state"))
			if fp == "" || (state != store.StateFP && state != store.StateACK && state != store.StateActive) {
				http.Error(w, `{"error":"fp and state=FP|ACK|ACTIVE required"}`, http.StatusBadRequest)
				return
			}
			var ttl time.Duration
			switch state {
			case store.StateFP:
				ttl = store.StateFPDuration
			case store.StateACK:
				ttl = store.StateACKDuration
			}
			if err := st.Cluster(clusterctx.ForRead(r)).SetViolationState(r.Context(), fp, state, ttl); err != nil {
				http.Error(w, `{"error":"state update failed"}`, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodGet:
			vtype := r.URL.Query().Get("type")
			stateFilter := r.URL.Query().Get("state")
			sinceID, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			rows, err := st.Cluster(clusterctx.ForRead(r)).QueryViolations(r.Context(), vtype, stateFilter, sinceID, limit)
			if err != nil {
				http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"violations": rows})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))))

	mux.Handle("/v1/violations/record", authed(mutationsRequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, `{"error":"postgresql not configured"}`, http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			VType       string          `json:"vtype"`
			RuleID      string          `json:"ruleId"`
			RuleName    string          `json:"ruleName"`
			Sev         string          `json:"sev"`
			NS          string          `json:"ns"`
			Pod         string          `json:"pod"`
			Fingerprint string          `json:"fingerprint"`
			Data        json.RawMessage `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
			body.Fingerprint == "" || (body.VType != "build" && body.VType != "deploy") {
			http.Error(w, `{"error":"vtype (build|deploy) and fingerprint required"}`, http.StatusBadRequest)
			return
		}
		if len(body.Data) == 0 {
			body.Data = json.RawMessage(`{}`)
		}
		st.Cluster(clusterctx.ForRead(r)).WriteViolation(r.Context(), body.VType, body.RuleID, body.RuleName, body.Sev, body.NS, body.Pod, body.Fingerprint, body.Data)
		w.WriteHeader(http.StatusNoContent)
	}))))
	mux.HandleFunc("/auth/login", authMgr.HandleLogin)
	mux.HandleFunc("/auth/logout", authMgr.HandleLogout)
	mux.HandleFunc("/auth/me", authMgr.HandleMe)

	adminMut := func(h http.HandlerFunc) http.Handler {
		return authed(mutationsRequireAdmin(http.HandlerFunc(h)))
	}
	mux.Handle("/api/auth/change-password", authed(http.HandlerFunc(authMgr.HandleChangePassword)))
	mux.Handle("/api/users", adminMut(authMgr.HandleUsers))
	mux.Handle("/api/users/", adminMut(authMgr.HandleUsersSub))
	mux.Handle("/api/groups", adminMut(authMgr.HandleGroups))
	mux.Handle("/api/groups/", adminMut(authMgr.HandleGroupItem))
	if st != nil {
		mux.Handle("/api/clusters", adminMut(clustersHandler(st)))
		mux.Handle("/api/clusters/", adminMut(clusterItemHandler(st)))
	}
	mux.Handle("/api/tokens", adminMut(authMgr.HandleTokens))
	mux.Handle("/api/tokens/", adminMut(authMgr.HandleTokenItem))

	internalSecret := os.Getenv("INTERNAL_PUSH_SECRET")
	mux.Handle("/internal/alert-log", internalPushAuth(internalSecret)(makeAlertLogHandler(st)))
	if internalSecret != "" {
		log.Printf("[kvisior] alert-log endpoint: POST /internal/alert-log (auth via X-Internal-Push-Secret)")
	} else {
		log.Printf("[kvisior] !!! SECURITY: INTERNAL_PUSH_SECRET unset — /internal/push/* and " +
			"/internal/alert-log will reject all requests (fail closed). Set INTERNAL_PUSH_SECRET to enable ingestion.")
	}

	if st != nil {
		apihandler.New(st).Register(mux, func(h http.Handler) http.Handler {
			return authed(mutationsRequireAdmin(h))
		})
		log.Printf("[kvisior] /api/{policies,acks,alerts} → direct DB; /api/events proxied to tracee-bridge")
	}

	if st != nil {
		mux.Handle("/scanner/results", authed(imageScansHandler(st)))
		mux.Handle("/scanner/workloads", authed(imageScanWorkloadsHandler(st)))
		mux.Handle("/scanner/histories", authed(imageHistoriesHandler(st)))
		mux.Handle("/audit/runs", authed(auditRunsHandler(st)))

		mux.Handle("/sentry/api/events", authed(auditEventsHandler(st)))
		mux.Handle("/sensor/api/forensic/diff/", authed(forensicDiffHandler(st)))
		log.Printf("[kvisior] /scanner/{results,histories}, /audit/runs, /sentry/api/events, /sensor/api/forensic/diff → direct DB; other /scanner/*, /audit/*, /sentry/*, /sensor/* proxied")
	}

	registerBackendProxies(mux, scheme, baseTransport, authed, fed)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if os.Getenv("POSTGRES_DSN") != "" && st == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"degraded","service":"kvisior","reason":"postgres unavailable"}`))
			return
		}
		body := map[string]any{"status": "ok", "service": "kvisior"}
		if policyConsumer != nil {
			malformed, dlqDelivered, dlqFailed := policyConsumer.MalformedStats()
			body["malformed_events"] = malformed
			body["malformed_live_events"] = kafkaconsumer.LiveMalformedCount()
			body["dlq_delivered"] = dlqDelivered
			body["dlq_failed"] = dlqFailed
			body["policy_stale_sec"] = policyConsumer.RulesStaleFor().Seconds()
		}
		json.NewEncoder(w).Encode(body)
	})

	distFS, err := fs.Sub(uiFiles, "dist")
	if err != nil {
		log.Fatalf("[kvisior] embed dist: %v", err)
	}
	fileServer := http.FileServer(http.FS(distFS))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if _, err := fs.Stat(distFS, path); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store, no-cache")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		w.Header().Set("X-Frame-Options", "sameorigin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		http.ServeFileFS(w, r, distFS, "index.html")
	})

	log.Printf("[kvisior] listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[kvisior] %v", err)
	}
}
