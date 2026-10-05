package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wolfee-watcher/pkg/logging"
	"github.com/wolfee-watcher/pkg/mtls"
	"github.com/wolfee-watcher/sentry-audit/internal/logsource"
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

	tailStatusInterval  = 4 * time.Second
	spoolStatusInterval = 15 * time.Second
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

func tailPath(node string) string {
	path := envOr("AUDIT_LOG_PATH", defaultAuditLog)
	for _, pair := range strings.Split(os.Getenv("AUDIT_LOG_NODE_PATHS"), ",") {
		if name, p, ok := strings.Cut(strings.TrimSpace(pair), "="); ok && name == node && p != "" {
			path = p
		}
	}
	return path
}

func reportTailStatus(ctx context.Context, node string, tailer *logtail.Tailer, kv *webhook.KvisiorForwarder) {
	ticker := time.NewTicker(tailStatusInterval)
	defer ticker.Stop()
	type report struct {
		Node string `json:"node"`
		logtail.Status
		ProbeDone   string `json:"probeDone,omitempty"`
		ProbeOK     bool   `json:"probeOk"`
		ProbeDetail string `json:"probeDetail,omitempty"`
	}
	failed, answered := false, ""
	for {
		body := report{Node: node, Status: tailer.Status()}
		for attempt := 0; attempt < 2; attempt++ {
			var reply struct {
				Probe string `json:"probe"`
			}
			err := kv.Call(ctx, http.MethodPost, "/internal/push/audit-log-status", body, &reply)
			if err != nil && !failed && ctx.Err() == nil {
				slog.Warn("audit_log_status_report_failed", "component", "sentry-audit/main", "error", err)
			}
			failed = err != nil
			if err != nil || reply.Probe == "" || reply.Probe == answered {
				break
			}
			answered = reply.Probe
			body = report{Node: node, Status: tailer.Status(), ProbeDone: reply.Probe}
			body.ProbeOK, body.ProbeDetail = logtail.Probe(body.Path)
			slog.Info("audit_log_probe", "component", "sentry-audit/main", "ok", body.ProbeOK, "detail", body.ProbeDetail)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func reportSpoolStatus(ctx context.Context, kv *webhook.KvisiorForwarder) {
	pod, _ := os.Hostname()
	ticker := time.NewTicker(spoolStatusInterval)
	defer ticker.Stop()
	failed := false
	for {
		body := struct {
			Pod string `json:"pod"`
			webhook.DeliveryStatus
		}{pod, kv.Status()}
		err := kv.Call(ctx, http.MethodPost, "/internal/push/audit-spool-status", body, nil)
		if err != nil && !failed && ctx.Err() == nil {
			slog.Warn("audit_spool_status_report_failed", "component", "sentry-audit/main", "error", err)
		}
		failed = err != nil
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func runWatcherWhenLeader(ctx context.Context, client kubernetes.Interface, emit func(webhook.AuditEvent), kv *webhook.KvisiorForwarder) {
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
				if kv != nil {
					go logsource.Run(leadCtx, client, mtls.Namespace(), kv)
				}
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
	var auditForwarder *webhook.KvisiorForwarder

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
		capacity := int64(1 << 30)
		if v, err := strconv.ParseInt(os.Getenv("AUDIT_SPOOL_MAX_BYTES"), 10, 64); err == nil && v > 0 {
			capacity = v
		}
		fwd, spoolErr := webhook.NewDurableForwarder(pushURL, secret, envOr("AUDIT_SPOOL_DIR", "/var/lib/sentry-audit/delivery"), capacity, nil)
		if spoolErr != nil {
			slog.Error("audit_spool_unavailable", "component", "sentry-audit/main", "error", spoolErr)
			fwd = webhook.NewKvisiorForwarder(pushURL, secret, nil)
		}
		auditForwarder = fwd
		if fwd != nil {
			if v, err := strconv.ParseFloat(os.Getenv("AUDIT_SPOOL_SHED_AT"), 64); err == nil && v > 0 && v <= 1 {
				fwd.ShedAt = v
			}
			if v, err := strconv.Atoi(os.Getenv("AUDIT_SPOOL_SHED_PER_ACTOR")); err == nil && v > 0 {
				fwd.ShedPerActor = v
			}
			fwd.WakeOnReachable()
			h.SetForwarder(fwd)
			defer fwd.Close()
			go reportSpoolStatus(ctx, fwd)
		} else {
			slog.Warn("push_forwarder_disabled",
				"component", "sentry-audit/main",
				"reason", "KVISIOR_PUSH_URL unset or invalid")
		}
		go runWatcherWhenLeader(ctx, client, h.Emit, fwd)

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
		node := envOr("NODE_NAME", "")
		if node == "" {
			node, _ = os.Hostname()
		}
		path := tailPath(node)
		tailer = logtail.New(path, os.Getenv("AUDIT_LOG_STATE_DIR"), filter, func(deliveryCtx context.Context, records []logtail.Record) error {
			batch := make([]json.RawMessage, 0, len(records))
			for _, rec := range records {
				raw, err := json.Marshal(rec)
				if err != nil {
					return err
				}
				batch = append(batch, raw)
			}
			err := fwd.Send(deliveryCtx, batch)
			if errors.Is(err, webhook.ErrPermanent) {
				return fmt.Errorf("%w: %v", logtail.ErrRejected, err)
			}
			return err
		})
		tailer.Probe = fwd.Reachable
		tailDone := make(chan struct{})
		go func() { defer close(tailDone); tailer.Run(ctx) }()
		defer func() { <-tailDone }()
		go reportTailStatus(ctx, node, tailer, fwd)
		slog.Info("logtail_started", "component", "sentry-audit/main", "path", path, "node", node)
	}

	apiMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		status := map[string]any{
			"status":  "ok",
			"service": "sentry-audit",
			"webhook": roles[roleWebhook],
			"logtail": roles[roleLogTail],
			"events":  st.Len(),
		}
		if auditForwarder != nil {
			status["delivery"] = auditForwarder.Status()
		}
		if tailer != nil {
			status["log"] = tailer.Status()
			status["logLines"] = tailer.Stats.Lines.Load()
			status["logSent"] = tailer.Stats.Sent.Load()
			status["logSkipped"] = tailer.Stats.Skipped.Load()
			status["logRejected"] = tailer.Stats.Rejected.Load()
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
