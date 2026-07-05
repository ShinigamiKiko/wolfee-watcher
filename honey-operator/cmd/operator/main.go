package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/wolfee-watcher/honey-operator/internal/api"
	"github.com/wolfee-watcher/honey-operator/internal/k8s"
	"github.com/wolfee-watcher/honey-operator/internal/watcher"
	"github.com/wolfee-watcher/pkg/logging"
)

func main() {
	logging.Setup("honey-operator")
	var (
		kubeconfig = flag.String("kubeconfig", "", "Path to kubeconfig (optional, uses in-cluster if empty)")
		addr       = flag.String("addr", "0.0.0.0:9095", "HTTP listen address")
	)
	flag.Parse()

	slog.Info("service_starting",
		"component", "honey-operator/main",
		"addr", *addr,
		"kubeconfig_configured", *kubeconfig != "",
		"kvisior_push_configured", os.Getenv("KVISIOR_PUSH_URL") != "",
		"internal_secret_configured", os.Getenv("INTERNAL_PUSH_SECRET") != "")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	client, err := buildClient(*kubeconfig)
	if err != nil {
		slog.Error("kubernetes_client_failed", "component", "honey-operator/main", "error", err)
		os.Exit(1)
	}
	slog.Info("dependency_ready", "component", "honey-operator/main", "dependency", "kubernetes")

	manager := k8s.New(client)

	w := watcher.New(manager, os.Getenv("KVISIOR_PUSH_URL"), os.Getenv("INTERNAL_PUSH_SECRET"))
	go w.Run(ctx, 5*time.Second)
	slog.Info("honeypot_watcher_started",
		"component", "honey-operator/main",
		"interval", (5 * time.Second).String())

	srv := api.New(ctx, *addr, manager, w)
	err = srv.Run()

	w.Close()
	if err != nil {
		slog.Error("service_failed", "component", "honey-operator/main", "error", err)
		os.Exit(1)
	}
	slog.Info("service_stopped", "component", "honey-operator/main")
}

func buildClient(kubeconfigFlag string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error

	switch {
	case kubeconfigFlag != "":
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigFlag)
	case os.Getenv("KUBECONFIG") != "":
		cfg, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	default:
		home := homedir.HomeDir()
		kc := filepath.Join(home, ".kube", "config")
		if _, statErr := os.Stat(kc); statErr == nil {
			cfg, err = clientcmd.BuildConfigFromFlags("", kc)
		} else {
			cfg, err = rest.InClusterConfig()
		}
	}
	if err != nil {
		return nil, fmt.Errorf("no kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}
