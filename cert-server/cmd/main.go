package main

import (
	"log/slog"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/wolfee-watcher/cert-server/internal/issuer"
	"github.com/wolfee-watcher/cert-server/internal/server"
	"github.com/wolfee-watcher/pkg/env"
	"github.com/wolfee-watcher/pkg/logging"
)

func main() {
	logging.Setup("cert-server")
	caCertPath := env.Str("CA_CERT_FILE", "/etc/wolfee-watcher/ca/ca.crt")
	caKeyPath := env.Str("CA_KEY_FILE", "/etc/wolfee-watcher/ca/ca.key")
	addr := env.Str("ADDR", ":8090")

	slog.Info("service_starting",
		"component", "cert-server/main",
		"addr", addr,
		"cert_lifetime", issuer.CertLifetime.String())

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		slog.Error("ca_cert_read_failed", "component", "cert-server/main", "error", err)
		os.Exit(1)
	}
	caKey, err := os.ReadFile(caKeyPath)
	if err != nil {
		slog.Error("ca_key_read_failed", "component", "cert-server/main", "error", err)
		os.Exit(1)
	}

	iss, err := issuer.New(caCert, caKey)
	if err != nil {
		slog.Error("issuer_init_failed", "component", "cert-server/main", "error", err)
		os.Exit(1)
	}
	slog.Info("ca_loaded",
		"component", "cert-server/main",
		"cert_lifetime", issuer.CertLifetime.String())

	cfg, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("kubernetes_config_failed", "component", "cert-server/main", "error", err)
		os.Exit(1)
	}
	k8s, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		slog.Error("kubernetes_client_failed", "component", "cert-server/main", "error", err)
		os.Exit(1)
	}
	slog.Info("dependency_ready", "component", "cert-server/main", "dependency", "kubernetes")

	srv := server.New(addr, iss, k8s)
	if err := srv.Run(); err != nil {
		slog.Error("service_failed", "component", "cert-server/main", "error", err)
		os.Exit(1)
	}
}
