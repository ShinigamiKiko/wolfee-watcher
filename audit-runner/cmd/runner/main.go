package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/wolfee-watcher/audit-runner/internal/jobs"
	"github.com/wolfee-watcher/audit-runner/internal/kv"
	"github.com/wolfee-watcher/audit-runner/internal/server"
	"github.com/wolfee-watcher/audit-runner/internal/store"
	"github.com/wolfee-watcher/pkg/env"
	"github.com/wolfee-watcher/pkg/logging"
)

func main() {
	logging.Setup("audit-runner")
	addr := flag.String("addr", env.Str("AUDIT_ADDR", "0.0.0.0:8080"), "Listen address")
	flag.Parse()

	slog.Info("service_starting",
		"component", "audit-runner/main",
		"addr", *addr,
		"kvisior_configured", os.Getenv("KVISIOR_URL") != "",
		"internal_secret_configured", os.Getenv("INTERNAL_PUSH_SECRET") != "")

	cfg, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("kubernetes_config_failed", "component", "audit-runner/main", "error", err)
		os.Exit(1)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		slog.Error("kubernetes_client_failed", "component", "audit-runner/main", "error", err)
		os.Exit(1)
	}
	slog.Info("dependency_ready", "component", "audit-runner/main", "dependency", "kubernetes")

	st := store.New()
	runner := jobs.New(client)
	kvClient := kv.New(os.Getenv("KVISIOR_URL"), os.Getenv("INTERNAL_PUSH_SECRET"))
	if os.Getenv("KVISIOR_URL") == "" {
		slog.Warn("durable_history_disabled",
			"component", "audit-runner/main",
			"reason", "KVISIOR_URL unset",
			"mode", "memory_only")
	} else {
		slog.Info("durable_history_enabled",
			"component", "audit-runner/main",
			"target", "kvisior")
	}
	ctx := context.Background()
	srv := server.New(ctx, *addr, st, runner, kvClient)

	if err := srv.Run(); err != nil {
		slog.Error("service_failed", "component", "audit-runner/main", "error", err)
		os.Exit(1)
	}
}
