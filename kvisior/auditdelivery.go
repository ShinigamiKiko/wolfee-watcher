package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wolfee-watcher/kvisior/internal/auditdelivery"
	"github.com/wolfee-watcher/kvisior/internal/auditengine"
	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/kvisior/internal/uibus"
	alertspkg "github.com/wolfee-watcher/pkg/alerts"
	"golang.org/x/net/netutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func auditDeliveryWorkers() int {
	value := os.Getenv("KVISIOR_AUDIT_WORKERS")
	if value == "" {
		return 4
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || n > 32 {
		log.Fatal("KVISIOR_AUDIT_WORKERS must be between 0 and 32")
	}
	return n
}
func auditInboxLimit() int {
	value := os.Getenv("KVISIOR_AUDIT_INBOX_MAX_PENDING")
	if value == "" {
		return 10000
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		log.Fatal("KVISIOR_AUDIT_INBOX_MAX_PENDING must be positive")
	}
	return n
}
func startDatabaseServices(ctx context.Context, st *store.Store, pool *pgxpool.Pool) {
	regCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if clusterctx.Hub() {
		log.Printf("[kvisior] hub mode: not registering a local cluster")
	} else if err := st.EnsureCluster(regCtx, clusterctx.Local()); err != nil {
		log.Printf("[kvisior] register local cluster %q: %v", clusterctx.Local(), err)
	}
	cancel()
	go st.RunRetention(ctx)
	go alertspkg.RunCleanup(ctx, pool)
	go alertspkg.RunWebhookDelivery(ctx, pool)
}

func startDatabaseServicesWhenReady(ctx context.Context, st *store.Store, pool *pgxpool.Pool) {
	whenDatabaseReady(ctx, func(c context.Context) error {
		_, err := store.NewFromPool(c, pool)
		return err
	}, func() {
		log.Printf("[kvisior] PostgreSQL is available — starting retention, alert cleanup and webhook delivery")
		startDatabaseServices(ctx, st, pool)
	})
}

func whenDatabaseReady(ctx context.Context, ready func(context.Context) error, start func()) {
	for delay := time.Second; ; delay = min(2*delay, 30*time.Second) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := ready(readyCtx)
		cancel()
		if err == nil {
			start()
			return
		}
	}
}

func positiveEnv(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		log.Fatalf("%s must be a positive integer", key)
	}
	return n
}

func newAuditReceiver(st *store.Store) *auditdelivery.Receiver {
	receiver := auditdelivery.NewReceiver(st, auditInboxLimit())
	receiver.PerCluster = positiveEnv("KVISIOR_AUDIT_CLUSTER_CONCURRENCY", receiver.PerCluster)
	receiver.BudgetBytes = max(int64(positiveEnv("KVISIOR_AUDIT_RECEIVE_BUDGET_BYTES", int(receiver.BudgetBytes))), auditdelivery.MaxAuditBody)
	return receiver
}

func auditRelay(target, secret string, transport http.RoundTripper) (http.HandlerFunc, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("audit receiver URL must be an HTTP(S) origin")
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = transport
	director := proxy.Director
	proxy.Director = func(r *http.Request) {
		cluster := clusterctx.ForPush(r)
		director(r)
		r.Host = u.Host
		r.Header.Del("Cookie")
		r.Header.Del("Authorization")
		r.Header.Set("X-Internal-Push-Secret", secret)
		r.Header.Set(clusterctx.Header, cluster)
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[audit-delivery] receiver unavailable: %v", err)
		http.Error(w, "audit receiver unavailable", 503)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		proxy.ServeHTTP(w, r.WithContext(ctx))
	}, nil
}

func runAuditDelivery(ctx context.Context, mode string) error {
	if os.Getenv("POSTGRES_DSN") == "" || os.Getenv("INTERNAL_PUSH_SECRET") == "" {
		return fmt.Errorf("audit delivery needs POSTGRES_DSN and INTERNAL_PUSH_SECRET")
	}
	if h, err := strconv.Atoi(os.Getenv("KVISIOR_AUDIT_RETENTION_HOURS")); err == nil && h > 0 {
		store.SetAuditRetention(time.Duration(h) * time.Hour)
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("POSTGRES_DSN"))
	if err != nil {
		return err
	}
	if cfg.MaxConns < 12 {
		cfg.MaxConns = 12
	}
	workers := auditDeliveryWorkers()
	if cfg.MaxConns < int32(workers*2+4) {
		cfg.MaxConns = int32(workers*2 + 4)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	st := store.FromPool(pool)
	brokers := []string{}
	if value := os.Getenv("KAFKA_BROKERS"); value != "" {
		brokers = strings.Split(value, ",")
	}
	bus := uibus.New(ctx, hub.New(5000), brokers)
	engine := auditengine.New(st, bus)
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); engine.Run(child) }()
	go func() { defer wg.Done(); auditdelivery.Run(child, st, engine, workers) }()
	defer func() { cancel(); wg.Wait() }()
	receiver := newAuditReceiver(st)
	mux := http.NewServeMux()
	wrap := pushSecretMiddleware(os.Getenv("INTERNAL_PUSH_SECRET"))
	if mode == "ingest" {
		mux.HandleFunc("/internal/push/audit", wrap(receiver.Events))
		mux.HandleFunc("/internal/push/audit-log", wrap(receiver.Log))
	}
	mux.HandleFunc("/internal/pull/audit-delivery", wrap(receiver.Status))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "kvisior-audit-" + mode})
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		c, stop := context.WithTimeout(r.Context(), time.Second)
		defer stop()
		if err := st.AuditInboxReady(c); err != nil {
			http.Error(w, "audit database unavailable", 503)
			return
		}
		w.WriteHeader(204)
	})
	addr := os.Getenv("KVISIOR_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	maxConns := positiveEnv("KVISIOR_INGEST_MAX_CONNS", 512)
	listen := func(addr string) (net.Listener, error) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		return netutil.LimitListener(ln, maxConns), nil
	}
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	ln, err := listen(addr)
	if err != nil {
		return err
	}
	servers := []*http.Server{server}
	failures := make(chan error, 2)
	go func() { failures <- server.Serve(ln) }()
	if tlsAddr := os.Getenv("KVISIOR_TLS_ADDR"); tlsAddr != "" {
		tlsServer := &http.Server{Addr: tlsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
		tlsLn, err := listen(tlsAddr)
		if err != nil {
			return err
		}
		servers = append(servers, tlsServer)
		go func() {
			failures <- tlsServer.ServeTLS(tlsLn, os.Getenv("KVISIOR_TLS_CERT_FILE"), os.Getenv("KVISIOR_TLS_KEY_FILE"))
		}()
	}
	log.Printf("[audit-delivery] role=%s workers=%d listening on %s (max %d connections)", mode, workers, addr, maxConns)
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-failures:
	}
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	for _, srv := range servers {
		srv.Shutdown(shutdown)
	}
	if serveErr == http.ErrServerClosed {
		serveErr = nil
	}
	return serveErr
}

func auditWorkersForPool(pool *pgxpool.Pool) int {
	workers := auditDeliveryWorkers()
	limit := int((pool.Config().MaxConns - 4) / 2)
	if limit < 1 {
		limit = 1
	}
	if workers > limit {
		log.Printf("[audit-delivery] limiting workers to %d for database pool", limit)
		workers = limit
	}
	return workers
}
