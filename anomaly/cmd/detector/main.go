package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/wolfee-watcher/anomaly-detector/internal/baseline"
	"github.com/wolfee-watcher/anomaly-detector/internal/broadcast"
	"github.com/wolfee-watcher/anomaly-detector/internal/checker"
	"github.com/wolfee-watcher/anomaly-detector/internal/consumer"
	"github.com/wolfee-watcher/anomaly-detector/internal/enricher"
	"github.com/wolfee-watcher/anomaly-detector/internal/integrations"
	"github.com/wolfee-watcher/anomaly-detector/internal/recon"
	"github.com/wolfee-watcher/anomaly-detector/internal/server"
	"github.com/wolfee-watcher/pkg/env"
	"github.com/wolfee-watcher/pkg/logging"
)

const defaultConsumerLockID int64 = 642596272900103939

func main() {
	logging.Setup("anomaly-detector")
	addr := flag.String("addr", env.Str("DETECTOR_ADDR", "0.0.0.0:8080"), "listen address")
	pgDSN := flag.String("postgres", env.Str("POSTGRES_DSN", ""), "PostgreSQL DSN")
	brokers := flag.String("kafka", env.Str("KAFKA_BROKERS", "kafka:9092"), "Kafka brokers, comma-separated")
	topic := flag.String("topic", env.Str("KAFKA_TOPIC", "tracee-events"), "Kafka topic to consume")
	obsPeriod := flag.Duration("observation-period",
		parseDuration(env.Str("OBSERVATION_PERIOD", "240h")),
		"baseline observation period (default: 10 days)")
	flag.Parse()

	if *brokers == "" {
		log.Fatal("KAFKA_BROKERS is required")
	}

	slog.Info("service_starting",
		"component", "anomaly-detector/main",
		"addr", *addr,
		"kafka_brokers", *brokers,
		"topic", *topic,
		"observation_period", obsPeriod.String(),
		"recon_threshold", recon.ScanThreshold,
		"recon_window_sec", int(recon.ScanWindow.Seconds()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := pgxpool.New(ctx, *pgDSN)
	if err != nil {
		log.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("postgres ping: %v", err)
	}

	go baseline.RunAnomalyCleanup(ctx, pool)

	integStore := integrations.NewStore(pool)
	if err := integStore.Load(ctx); err != nil {
		slog.Warn("integrations_load_failed",
			"component", "anomaly-detector/main",
			"error", err)
	}
	integMgr := integrations.NewManager(integStore)

	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("k8s config: %v", err)
	}
	k8s, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("k8s client: %v", err)
	}

	base := baseline.New(ctx, pool, *obsPeriod)
	if err := base.Load(ctx); err != nil {
		slog.Warn("baseline_load_failed",
			"component", "anomaly-detector/main",
			"error", err)
	}

	enr := enricher.New(k8s)
	enr.StartBackgroundRefresh(ctx)

	rec := recon.New()
	chk := checker.New(k8s)

	bcast := broadcast.New()
	cons := consumer.New(ctx, strings.Split(*brokers, ","), *topic, pool, base, chk, enr, bcast)
	cons.SetNotifier(notifierAdapter{mgr: integMgr})
	srv := server.New(ctx, *addr, pool, base, cons, rec, bcast, integStore, integMgr)

	go func() {
		if err := srv.Run(); err != nil {
			log.Fatalf("server: %v", err)
		}
	}()

	startConsumer(ctx, pool, cons)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	slog.Info("service_stopping", "component", "anomaly-detector/main")
	rec.Stop()
	cancel()

	cons.Close()
}

func startConsumer(ctx context.Context, pool *pgxpool.Pool, cons *consumer.Consumer) {
	role := strings.ToLower(strings.TrimSpace(env.Str("ANOMALY_CONSUMER_ROLE", "auto")))
	switch role {
	case "auto", "":
		go runConsumerWithAdvisoryLock(ctx, pool, cons)
	case "leader", "direct", "standalone":
		slog.Warn("consumer_starting_without_lock",
			"component", "anomaly-detector/main",
			"role", role)
		go func() {
			if err := runConsumer(ctx, cons); err != nil {
				log.Fatalf("consumer: %v", err)
			}
		}()
	case "follower", "disabled", "off":
		slog.Info("consumer_disabled",
			"component", "anomaly-detector/main",
			"role", role)
	default:
		slog.Warn("unknown_consumer_role",
			"component", "anomaly-detector/main",
			"role", role,
			"fallback", "advisory_lock")
		go runConsumerWithAdvisoryLock(ctx, pool, cons)
	}
}

func runConsumerWithAdvisoryLock(ctx context.Context, pool *pgxpool.Pool, cons *consumer.Consumer) {
	identity := podIdentity()
	lockID := consumerLockID()
	slog.Info("consumer_lock_enabled",
		"component", "anomaly-detector/main",
		"lock_id", lockID,
		"identity", identity)

	for ctx.Err() == nil {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("consumer_lock_connection_failed",
					"component", "anomaly-detector/main",
					"lock_id", lockID,
					"identity", identity,
					"error", err)
				waitOrDone(ctx, 5*time.Second)
			}
			continue
		}

		var acquired bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockID).Scan(&acquired); err != nil {
			conn.Release()
			if ctx.Err() == nil {
				slog.Warn("consumer_lock_acquire_failed",
					"component", "anomaly-detector/main",
					"lock_id", lockID,
					"identity", identity,
					"error", err)
				waitOrDone(ctx, 5*time.Second)
			}
			continue
		}
		if !acquired {
			conn.Release()
			waitOrDone(ctx, 5*time.Second)
			continue
		}

		slog.Info("consumer_leadership_acquired",
			"component", "anomaly-detector/main",
			"lock_id", lockID,
			"identity", identity)
		leadCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- runConsumer(leadCtx, cons) }()

		ticker := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-ctx.Done():
				cancel()
				ticker.Stop()
				releaseConsumerLock(conn, lockID)
				return
			case err := <-done:
				cancel()
				ticker.Stop()
				releaseConsumerLock(conn, lockID)
				if ctx.Err() == nil && err != nil {
					log.Fatalf("consumer: %v", err)
				}
				return
			case <-ticker.C:
				var one int
				if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
					cancel()
					ticker.Stop()
					conn.Release()
					log.Fatalf("consumer advisory lock session lost: %v", err)
				}
			}
		}
	}
}

func runConsumer(ctx context.Context, cons *consumer.Consumer) error {
	if err := cons.Run(ctx); err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
		return err
	}
	return nil
}

func releaseConsumerLock(conn *pgxpool.Conn, lockID int64) {
	defer conn.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", lockID); err != nil {
		slog.Warn("consumer_lock_release_failed",
			"component", "anomaly-detector/main",
			"lock_id", lockID,
			"error", err)
		return
	}
	slog.Info("consumer_lock_released",
		"component", "anomaly-detector/main",
		"lock_id", lockID)
}

func waitOrDone(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func consumerLockID() int64 {
	v := strings.TrimSpace(os.Getenv("ANOMALY_CONSUMER_LOCK_ID"))
	if v == "" {
		return defaultConsumerLockID
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n == 0 {
		slog.Warn("invalid_int_env",
			"component", "anomaly-detector/main",
			"key", "ANOMALY_CONSUMER_LOCK_ID",
			"value", v,
			"default", defaultConsumerLockID)
		return defaultConsumerLockID
	}
	return n
}

func podIdentity() string {
	for _, key := range []string{"POD_NAME", "HOSTNAME"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "anomaly-detector"
}

type notifierAdapter struct{ mgr *integrations.Manager }

func (a notifierAdapter) Notify(ev *consumer.AnomalyEvent) {
	if ev == nil || a.mgr == nil {
		return
	}
	a.mgr.Dispatch(integrations.EventInfo{
		ID:        ev.ID,
		Ts:        ev.Ts,
		Kind:      string(ev.Kind),
		Namespace: ev.SrcNamespace,
		Workload:  ev.SrcDeployment,
		Pod:       ev.SrcPod,
		Process:   ev.SrcProcess,
		Detail:    ev.Detail,
		DstIP:     ev.DstIP,
		DstPort:   ev.DstPort,
		Syscall:   ev.Syscall,
	})
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return baseline.DefaultObservationPeriod
	}
	return d
}
