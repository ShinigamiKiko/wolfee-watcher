package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/wolfee-watcher/forensic-watcher/internal/fswatch"
	"github.com/wolfee-watcher/forensic-watcher/internal/logcollect"
	"github.com/wolfee-watcher/forensic-watcher/internal/server"
	"github.com/wolfee-watcher/pkg/logging"
)

func main() {
	logging.Setup("forensic-watcher")
	var (
		kubeconfig     = flag.String("kubeconfig", "", "Path to kubeconfig (optional)")
		addr           = flag.String("addr", "0.0.0.0:9090", "HTTP listen address")
		containerdRoot = flag.String("containerd-root", "/var/lib/containerd", "Path to containerd root (hostPath mount)")
		podLogsRoot    = flag.String("pod-logs-root", "", "Path to the kubelet pod log dir (hostPath mount of /var/log/pods); empty disables node-local log collection")
	)
	flag.Parse()

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		slog.Error("required_config_missing", "component", "forensic-watcher/main", "key", "NODE_NAME")
		os.Exit(1)
	}

	slog.Info("service_starting",
		"component", "forensic-watcher/main",
		"node", nodeName,
		"addr", *addr,
		"containerd_root", *containerdRoot,
		"pod_logs_enabled", *podLogsRoot != "",
		"kubeconfig_configured", *kubeconfig != "")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	client, err := buildClient(*kubeconfig)
	if err != nil {
		slog.Error("kubernetes_client_failed", "component", "forensic-watcher/main", "error", err)
		os.Exit(1)
	}
	slog.Info("dependency_ready", "component", "forensic-watcher/main", "dependency", "kubernetes")

	central := fswatch.NewCentralClient()
	if central == nil {
		slog.Warn("diff_history_disabled",
			"component", "forensic-watcher/main",
			"reason", "KVISIOR_URL unset",
			"mode", "memory_only")
	}

	watcher := fswatch.New(nodeName, *containerdRoot, central, client)

	if *podLogsRoot != "" {
		if lc := logcollect.New(*podLogsRoot, nodeName,
			central, strings.Split(os.Getenv("LOG_EXCLUDE_NAMESPACES"), ",")); lc != nil {
			go lc.Run(ctx)
			slog.Info("node_log_collection_enabled",
				"component", "forensic-watcher/main",
				"node", nodeName,
				"exclude_namespaces", os.Getenv("LOG_EXCLUDE_NAMESPACES"))
		} else {
			slog.Warn("node_log_collection_disabled",
				"component", "forensic-watcher/main",
				"reason", "KVISIOR_URL unset")
		}
	}

	srv := server.New(*addr, watcher, nodeName)

	slog.Info("forensic_watcher_ready",
		"component", "forensic-watcher/main",
		"node", nodeName,
		"addr", *addr,
		"central_configured", central != nil,
		"log_collection", *podLogsRoot != "")

	go func() {
		if err := srv.Run(ctx); err != nil {
			slog.Error("service_failed", "component", "forensic-watcher/main", "error", err)
			cancel()
		}
	}()

	go watcher.Run(ctx)

	<-ctx.Done()
	slog.Info("service_stopping", "component", "forensic-watcher/main", "node", nodeName)
}

func buildClient(kubeconfigFlag string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error
	if kubeconfigFlag != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigFlag)
	} else if kc := os.Getenv("KUBECONFIG"); kc != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kc)
	} else if home := homedir.HomeDir(); home != "" {
		kc := filepath.Join(home, ".kube", "config")
		if _, statErr := os.Stat(kc); statErr == nil {
			cfg, err = clientcmd.BuildConfigFromFlags("", kc)
		} else {
			cfg, err = rest.InClusterConfig()
		}
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}
