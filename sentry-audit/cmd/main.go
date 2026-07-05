package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/wolfee-watcher/pkg/logging"
	"github.com/wolfee-watcher/sentry-audit/internal/alerter"
	"github.com/wolfee-watcher/sentry-audit/internal/selfregister"
	"github.com/wolfee-watcher/sentry-audit/internal/server"
	"github.com/wolfee-watcher/sentry-audit/internal/store"
	"github.com/wolfee-watcher/sentry-audit/internal/webhook"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	logging.Setup("sentry-audit")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("service_starting",
		"component", "sentry-audit/main",
		"kvisior_push_configured", os.Getenv("KVISIOR_PUSH_URL") != "",
		"internal_secret_configured", os.Getenv("INTERNAL_PUSH_SECRET") != "")

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
	slog.Info("dependency_ready", "component", "sentry-audit/main", "dependency", "kubernetes")

	dnsNames := []string{
		"sentry-audit",
		"sentry-audit.wolfee-watcher",
		"sentry-audit.wolfee-watcher.svc",
		"sentry-audit.wolfee-watcher.svc.cluster.local",
	}
	cert, err := selfregister.LoadOrCreateCert(ctx, client, dnsNames)
	if err != nil {
		slog.Error("tls_cert_setup_failed", "component", "sentry-audit/main", "error", err)
		os.Exit(1)
	}
	slog.Info("tls_certificate_ready", "component", "sentry-audit/main", "dns_names", dnsNames)

	if err := selfregister.Register(ctx, client, cert.CAPem); err != nil {
		slog.Error("webhook_register_failed", "component", "sentry-audit/main", "error", err)
		os.Exit(1)
	}
	slog.Info("webhook_registered", "component", "sentry-audit/main")

	st := store.New()

	al := alerter.New(ctx)

	h := webhook.NewHandler(st, st)
	h.SetEvaluator(al)
	fwd := webhook.NewKvisiorForwarder(os.Getenv("KVISIOR_PUSH_URL"), os.Getenv("INTERNAL_PUSH_SECRET"), nil)
	if fwd != nil {
		h.SetForwarder(fwd)
		slog.Info("push_forwarder_enabled",
			"component", "sentry-audit/main",
			"target", "kvisior")
	} else {
		slog.Warn("push_forwarder_disabled",
			"component", "sentry-audit/main",
			"reason", "KVISIOR_PUSH_URL unset or invalid")
	}

	webhookMux := http.NewServeMux()
	webhookMux.HandleFunc("/validate", h.HandlePolicy)
	webhookMux.HandleFunc("/events", h.HandleEvents)

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"service": "sentry-audit",
			"pg":      false,
			"events":  st.Len(),
		})
	})
	apiMux.HandleFunc("/api/events", h.HandleGetEvents)

	slog.Info("sentry_audit_ready",
		"component", "sentry-audit/main",
		"mode", "stateless",
		"events_persisted_by", "kvisior")
	if err := server.Run(ctx, cert.TLSConfig, webhookMux, apiMux); err != nil {
		slog.Error("service_failed", "component", "sentry-audit/main", "error", err)
		os.Exit(1)
	}

	if fwd != nil {
		fwd.Close()
	}
	al.Close()
	slog.Info("service_stopped", "component", "sentry-audit/main")
}
