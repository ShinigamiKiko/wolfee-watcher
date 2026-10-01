package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wolfee-watcher/pkg/logging"
	"github.com/wolfee-watcher/pkg/mtls"
	"github.com/wolfee-watcher/sentry-audit/internal/logtail"
	"github.com/wolfee-watcher/sentry-audit/internal/selfregister"
	"github.com/wolfee-watcher/sentry-audit/internal/server"
	"github.com/wolfee-watcher/sentry-audit/internal/store"
	"github.com/wolfee-watcher/sentry-audit/internal/watcher"
	"github.com/wolfee-watcher/sentry-audit/internal/webhook"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	roleWebhook = "webhook"
	roleLogTail = "logtail"

	defaultAuditLog   = "/var/log/kubernetes/audit/audit.log"
	watcherLeaseName  = "sentry-audit-watcher"
	leaseDuration     = 15 * time.Second
	leaseRenewTimeout = 10 * time.Second
	leaseRetryPeriod  = 2 * time.Second
)

func parseRoles(v string) map[string]bool {
	roles := map[string]bool{}
	for _, r := range strings.Split(v, ",") {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" {
			roles[r] = true
		}
	}
	if len(roles) == 0 {
		roles[roleWebhook] = true
	}
	return roles
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envList(key string, fallback []string) []string {
	v, set := os.LookupEnv(key)
	if !set {
		return fallback
	}
	out := []string{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runWatcherWhenLeader(ctx context.Context, client kubernetes.Interface, emit func(webhook.AuditEvent)) {
	identity, _ := os.Hostname()
	if identity == "" {
		identity = "sentry-audit"
	}
	cfg := leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta:  metav1.ObjectMeta{Namespace: mtls.Namespace(), Name: watcherLeaseName},
			Client:     client.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{Identity: identity},
		},
		ReleaseOnCancel: true,
		LeaseDuration:   leaseDuration,
		RenewDeadline:   leaseRenewTimeout,
		RetryPeriod:     leaseRetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leadCtx context.Context) {
				slog.Info("watcher_leader_acquired", "component", "sentry-audit/main", "identity", identity)
				if err := watcher.New(client, emit).Run(leadCtx); err != nil && leadCtx.Err() == nil {
					slog.Error("informer_watch_failed", "component", "sentry-audit/main", "error", err)
				}
			},
			OnStoppedLeading: func() {
				slog.Warn("watcher_leader_lost", "component", "sentry-audit/main", "identity", identity)
			},
		},
	}
	for ctx.Err() == nil {
		leaderelection.RunOrDie(ctx, cfg)
		select {
		case <-ctx.Done():
		case <-time.After(leaseRetryPeriod):
		}
	}
}

func main() {
	logging.Setup("sentry-audit")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	roles := parseRoles(os.Getenv("SENTRY_ROLES"))
	pushURL, secret := os.Getenv("KVISIOR_PUSH_URL"), os.Getenv("INTERNAL_PUSH_SECRET")
	slog.Info("service_starting",
		"component", "sentry-audit/main",
		"webhook", roles[roleWebhook],
		"logtail", roles[roleLogTail],
		"kvisior_push_configured", pushURL != "",
		"internal_secret_configured", secret != "")

	st := store.New()
	var tlsCfg *tls.Config
	var webhookMux http.Handler
	apiMux := http.NewServeMux()
	var tailer *logtail.Tailer

	if roles[roleWebhook] {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			slog.Error("kubernetes_config_failed", "component", "sentry-audit/main", "error", err)
			os.Exit(1)
		}
		client, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			slog.Error("kubernetes_client_failed", "component", "sentry-audit/main", "error", err)
			os.Exit(1)
		}

		dnsNames := mtls.ServiceDNSNames("sentry-audit")
		cert, err := selfregister.LoadOrCreateCert(ctx, client, dnsNames)
		if err != nil {
			slog.Error("tls_cert_setup_failed", "component", "sentry-audit/main", "error", err)
			os.Exit(1)
		}
		if err := selfregister.Register(ctx, client, cert.CAPem); err != nil {
			slog.Error("webhook_register_failed", "component", "sentry-audit/main", "error", err)
			os.Exit(1)
		}
		slog.Info("webhook_registered", "component", "sentry-audit/main", "dns_names", dnsNames)
		tlsCfg = cert.TLSConfig

		h := webhook.NewHandler(st, st)
		if fwd := webhook.NewKvisiorForwarder(pushURL, secret, nil); fwd != nil {
			h.SetForwarder(fwd)
			defer fwd.Close()
		} else {
			slog.Warn("push_forwarder_disabled",
				"component", "sentry-audit/main",
				"reason", "KVISIOR_PUSH_URL unset or invalid")
		}
		go runWatcherWhenLeader(ctx, client, h.Emit)

		mux := http.NewServeMux()
		mux.HandleFunc("/validate", h.HandlePolicy)
		mux.HandleFunc("/events", h.HandleEvents)
		webhookMux = mux
		apiMux.HandleFunc("/api/events", h.HandleGetEvents)
	}

	if roles[roleLogTail] {
		fwd := webhook.NewLogForwarder(pushURL, secret, nil)
		if fwd == nil {
			slog.Error("logtail_needs_kvisior", "component", "sentry-audit/main",
				"reason", "KVISIOR_PUSH_URL unset or invalid")
			os.Exit(1)
		}
		defer fwd.Close()
		filter := logtail.DefaultFilter()
		filter.DropResources = envList("AUDIT_LOG_DROP_RESOURCES", filter.DropResources)
		filter.DropUsers = envList("AUDIT_LOG_DROP_USERS", filter.DropUsers)
		path := envOr("AUDIT_LOG_PATH", defaultAuditLog)
		tailer = logtail.New(path, os.Getenv("AUDIT_LOG_STATE_DIR"), filter, func(records []logtail.Record) {
			batch := make([]json.RawMessage, 0, len(records))
			for _, rec := range records {
				if raw, err := json.Marshal(rec); err == nil {
					batch = append(batch, raw)
				}
			}
			fwd.Forward(batch)
		})
		go tailer.Run(ctx)
		slog.Info("logtail_started", "component", "sentry-audit/main", "path", path)
	}

	apiMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		status := map[string]any{
			"status":  "ok",
			"service": "sentry-audit",
			"webhook": roles[roleWebhook],
			"logtail": roles[roleLogTail],
			"events":  st.Len(),
		}
		if tailer != nil {
			status["logLines"] = tailer.Stats.Lines.Load()
			status["logSent"] = tailer.Stats.Sent.Load()
			status["logSkipped"] = tailer.Stats.Skipped.Load()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	slog.Info("sentry_audit_ready", "component", "sentry-audit/main", "events_persisted_by", "kvisior")
	if err := server.Run(ctx, tlsCfg, webhookMux, apiMux); err != nil {
		slog.Error("service_failed", "component", "sentry-audit/main", "error", err)
		os.Exit(1)
	}
	slog.Info("service_stopped", "component", "sentry-audit/main")
}
