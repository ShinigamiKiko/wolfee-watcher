package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wolfee-watcher/scanner-agent/internal/alerter"

	"github.com/wolfee-watcher/pkg/env"
	"github.com/wolfee-watcher/pkg/logging"
	"github.com/wolfee-watcher/scanner-agent/internal/api"
	"github.com/wolfee-watcher/scanner-agent/internal/bdu"
	"github.com/wolfee-watcher/scanner-agent/internal/epss"
	"github.com/wolfee-watcher/scanner-agent/internal/grype"
	"github.com/wolfee-watcher/scanner-agent/internal/harbor"
	"github.com/wolfee-watcher/scanner-agent/internal/k8s"
)

func main() {
	logging.Setup("scanner-agent")
	addr := env.Str("SCANNER_ADDR", ":9090")
	grypeBin := env.Str("GRYPE_PATH", "grype")
	cacheDir := env.Str("GRYPE_CACHE_DIR", "/grype-cache")

	workspaceDir := env.Str("SCAN_WORKSPACE_DIR", "/scan-workspace")
	nvdAPIKey := env.Str("NVD_API_KEY", "")

	slog.Info("service_starting",
		"component", "scanner-agent/main",
		"addr", addr,
		"engine", "grype",
		"grype_path", grypeBin,
		"cache_dir", cacheDir,
		"workspace_dir", workspaceDir,
		"nvd_api_key_configured", nvdAPIKey != "")

	k8sClient, err := k8s.New()
	if err != nil {
		slog.Error("kubernetes_client_failed", "component", "scanner-agent/main", "error", err)
		os.Exit(1)
	}
	slog.Info("dependency_ready", "component", "scanner-agent/main", "dependency", "kubernetes")

	scanner := grype.New(grypeBin, cacheDir, workspaceDir)

	scanner.SweepWorkspace()

	if env.Str("GRYPE_SKIP_DB_UPDATE", "false") != "true" {
		slog.Info("grype_db_update_started", "component", "scanner-agent/main")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		if err := scanner.EnsureDB(ctx); err != nil {
			slog.Warn("grype_db_warmup_failed",
				"component", "scanner-agent/main",
				"error", err,
				"action", "retry_on_first_scan")
		} else {
			slog.Info("dependency_ready", "component", "scanner-agent/main", "dependency", "grype_db")
		}
		cancel()
	} else {
		slog.Info("grype_db_update_skipped", "component", "scanner-agent/main")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	enricher := epss.New(ctx, nvdAPIKey)

	bduLocal := os.Getenv("BDU_LOCAL_PATH")
	bduURL := os.Getenv("BDU_ARCHIVE_URL")
	bduNoDetail := os.Getenv("BDU_NO_DETAIL") != ""
	if os.Getenv("BDU_DISABLE") != "" {
		slog.Info("bdu_enricher_disabled", "component", "scanner-agent/main")
	} else {
		bduEnricher := bdu.New(bdu.Options{
			LocalPath:  bduLocal,
			ArchiveURL: bduURL,
			NoDetail:   bduNoDetail,
		})
		bduEnricher.Start(ctx)
		enricher.WithBDU(bduEnricher)
		slog.Info("bdu_enricher_enabled",
			"component", "scanner-agent/main",
			"local_path_configured", bduLocal != "",
			"archive_url_configured", bduURL != "",
			"no_detail", bduNoDetail)
	}

	harborStore := harbor.New(ctx)
	if harborStore != nil {
		harborStore.Start(ctx)
		slog.Info("harbor_credentials_source_enabled",
			"component", "scanner-agent/main",
			"source", "kvisior_integrations_pull")
	} else {
		slog.Info("harbor_credentials_source_disabled",
			"component", "scanner-agent/main",
			"reason", "KVISIOR_URL unset")
	}

	srv := api.New(ctx, k8sClient, scanner, enricher, addr, harborStore)

	al := alerter.New(ctx, srv)

	if err := srv.Run(); err != nil {
		slog.Error("service_failed", "component", "scanner-agent/main", "error", err)
		os.Exit(1)
	}

	al.Close()
	slog.Info("service_stopped", "component", "scanner-agent/main")
}
