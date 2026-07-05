package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/util/homedir"

	"github.com/wolfee-watcher/pkg/env"
	"github.com/wolfee-watcher/pkg/logging"
	"github.com/wolfee-watcher/pkg/mtls"
	"github.com/wolfee-watcher/sensor/internal/alerter"
	"github.com/wolfee-watcher/sensor/internal/central"
	"github.com/wolfee-watcher/sensor/internal/collector"
	"github.com/wolfee-watcher/sensor/internal/logstore"
	"github.com/wolfee-watcher/sensor/internal/server"
)

func main() {
	logging.Setup("sensor")
	var (
		kubeconfig = flag.String("kubeconfig", "", "Path to kubeconfig (optional, uses in-cluster if empty)")
		addr       = flag.String("addr", "0.0.0.0:8080", "HTTP listen address")
		interval   = flag.Duration("interval", 60*time.Second, "Snapshot refresh interval")
	)
	flag.Parse()

	role := strings.ToLower(env.Str("SENSOR_ROLE", "auto"))
	slog.Info("service_starting",
		"component", "sensor/main",
		"addr", *addr,
		"role", role,
		"snapshot_interval", interval.String(),
		"kubeconfig_configured", *kubeconfig != "")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	client, cfg, err := buildClient(*kubeconfig)
	if err != nil {
		slog.Error("kubernetes_client_failed", "component", "sensor/main", "error", err)
		os.Exit(1)
	}
	slog.Info("dependency_ready", "component", "sensor/main", "dependency", "kubernetes")

	var ls *logstore.Store
	centralClient := central.New()
	if centralClient != nil {
		ls = logstore.New(centralClient, client)
		slog.Info("log_history_enabled",
			"component", "sensor/main",
			"mode", "kvisior")
	} else {
		slog.Warn("log_history_disabled",
			"component", "sensor/main",
			"reason", "KVISIOR_URL unset",
			"mode", "kubelet_proxy")
	}

	var httpClient *http.Client
	if holder, err := mtls.NewCertHolder(ctx, mtls.Sensor); err == nil {
		if c, err := mtls.NewForensicClient(holder); err == nil {
			httpClient = c
			slog.Info("mtls_client_ready",
				"component", "sensor/main",
				"mode", "dynamic_certs")
		}
	} else {
		slog.Warn("mtls_client_unavailable",
			"component", "sensor/main",
			"fallback", "plain_http",
			"error", err)
	}
	srv := server.New(ctx, *addr, client, ls, httpClient)

	al := alerter.New(ctx, srv)

	switch role {
	case "leader":
		slog.Warn("snapshot_collector_forced_leader",
			"component", "sensor/main",
			"role", role)
		go runDataLoops(ctx, client, cfg, srv, *interval)
	case "follower":
		slog.Info("snapshot_collector_disabled",
			"component", "sensor/main",
			"role", role)
	default:
		slog.Info("leader_election_enabled",
			"component", "sensor/main",
			"role", role,
			"lease_name", env.Str("SENSOR_LEASE_NAME", "sensor-snapshot-leader"))
		go runLeaderElection(ctx, client, cfg, srv, *interval)
	}

	if err := srv.Run(); err != nil {
		slog.Error("service_failed", "component", "sensor/main", "error", err)
		os.Exit(1)
	}

	al.Close()
	slog.Info("service_stopped", "component", "sensor/main")
}

func runDataLoops(ctx context.Context, client kubernetes.Interface, cfg *rest.Config, srv *server.Server, interval time.Duration) {
	go collector.RunLoop(ctx, client, cfg, interval, func(snap *collector.Snapshot) {
		srv.SetSnapshot(snap)
	})
	<-ctx.Done()
}

func runLeaderElection(ctx context.Context, client kubernetes.Interface, cfg *rest.Config, srv *server.Server, interval time.Duration) {
	identity := detectIdentity()
	leaseNS := detectNamespace()
	leaseName := env.Str("SENSOR_LEASE_NAME", "sensor-snapshot-leader")
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Namespace: leaseNS,
			Name:      leaseName,
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: identity,
		},
	}
	cfgLE := leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leadCtx context.Context) {
				slog.Info("leader_election_acquired",
					"component", "sensor/main",
					"identity", identity,
					"lease_namespace", leaseNS,
					"lease_name", leaseName)
				runDataLoops(leadCtx, client, cfg, srv, interval)
			},
			OnStoppedLeading: func() {
				slog.Warn("leader_election_lost",
					"component", "sensor/main",
					"identity", identity,
					"lease_namespace", leaseNS,
					"lease_name", leaseName)
			},
			OnNewLeader: func(id string) {
				if id != identity {
					slog.Info("leader_election_observed_new_leader",
						"component", "sensor/main",
						"identity", identity,
						"leader", id,
						"lease_namespace", leaseNS,
						"lease_name", leaseName)
				}
			},
		},
	}

	for {
		leaderelection.RunOrDie(ctx, cfgLE)
		if ctx.Err() != nil {
			return
		}
		slog.Warn("leader_election_restarting",
			"component", "sensor/main",
			"identity", identity,
			"lease_namespace", leaseNS,
			"lease_name", leaseName)
		time.Sleep(2 * time.Second)
	}
}

func detectIdentity() string {
	if hn, err := os.Hostname(); err == nil && hn != "" {
		return hn
	}
	return fmt.Sprintf("sensor-%d", time.Now().UnixNano())
}

func detectNamespace() string {
	if ns := strings.TrimSpace(os.Getenv("POD_NAMESPACE")); ns != "" {
		return ns
	}
	const saNSPath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	if raw, err := os.ReadFile(saNSPath); err == nil {
		if ns := strings.TrimSpace(string(raw)); ns != "" {
			return ns
		}
	}
	return "wolfee-watcher"
}

func buildClient(kubeconfigFlag string) (kubernetes.Interface, *rest.Config, error) {
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
		return nil, nil, fmt.Errorf("no kubeconfig found: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	return client, cfg, nil
}
