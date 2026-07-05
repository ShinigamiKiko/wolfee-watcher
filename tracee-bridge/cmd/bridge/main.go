package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"strings"

	"github.com/wolfee-watcher/pkg/env"
	"github.com/wolfee-watcher/pkg/logging"
	"github.com/wolfee-watcher/tracee-bridge/internal/hub"
	"github.com/wolfee-watcher/tracee-bridge/internal/server"
)

func main() {
	logging.Setup("tracee-bridge")
	addr := flag.String("addr", env.Str("BRIDGE_ADDR", "0.0.0.0:8080"), "Listen address")
	pgDSN := flag.String("postgres", env.Str("POSTGRES_DSN", ""), "PostgreSQL DSN for history sink (optional)")
	brokers := flag.String("kafka", env.Str("KAFKA_BROKERS", "kafka:9092"), "Kafka brokers, comma-separated")
	topic := flag.String("topic", env.Str("KAFKA_TOPIC", "tracee-events"), "Kafka topic")
	flag.Parse()

	if *brokers == "" {
		slog.Error("required_config_missing", "component", "tracee-bridge/main", "key", "KAFKA_BROKERS")
		os.Exit(1)
	}

	if os.Getenv("KVISIOR_URL") == "" {
		slog.Error("required_config_missing", "component", "tracee-bridge/main", "key", "KVISIOR_URL")
		os.Exit(1)
	}

	slog.Info("service_starting",
		"component", "tracee-bridge/main",
		"addr", *addr,
		"brokers", *brokers,
		"topic", *topic,
		"postgres_configured", *pgDSN != "",
		"kvisior_configured", true)

	ctx := context.Background()
	h := hub.New(ctx, strings.Split(*brokers, ","), *topic, *pgDSN)
	srv := server.New(ctx, h, *addr)

	if err := srv.Run(); err != nil {
		slog.Error("service_failed",
			"component", "tracee-bridge/main",
			"error", err)
		os.Exit(1)
	}
}
