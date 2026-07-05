package consumer

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
	alertspkg "github.com/wolfee-watcher/pkg/alerts"

	"github.com/wolfee-watcher/anomaly-detector/internal/baseline"
	"github.com/wolfee-watcher/anomaly-detector/internal/broadcast"
	"github.com/wolfee-watcher/anomaly-detector/internal/checker"
	"github.com/wolfee-watcher/anomaly-detector/internal/enricher"
	"github.com/wolfee-watcher/anomaly-detector/internal/recon"
)

const filelessWindow = 30 * time.Second

var ignoredNamespaces = map[string]bool{
	"wolfee-watcher":  true,
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"calico-system":   true,
	"cert-manager":    true,
	"metallb-system":  true,
}

type AnomalyKind string

const (
	KindPolicyBlocked    AnomalyKind = "policy_blocked"
	KindUnauthorizedFlow AnomalyKind = "unauthorized_flow"
	KindPortScan         AnomalyKind = "port_scan"
	KindSuspiciousPort   AnomalyKind = "suspicious_port"
	KindRawSocket        AnomalyKind = "raw_socket"
	KindSuspiciousBind   AnomalyKind = "suspicious_bind"
	KindUnexpectedListen AnomalyKind = "unexpected_listen"
	KindProcessInjection AnomalyKind = "process_injection"
	KindFilelessExec     AnomalyKind = "fileless_exec"
	KindKernelModuleLoad AnomalyKind = "kernel_module_load"
	KindEBPFLoad         AnomalyKind = "ebpf_load"
	KindContainerEscape  AnomalyKind = "container_escape"
	KindPrivEscalation   AnomalyKind = "privilege_escalation"
	KindIOUring          AnomalyKind = "io_uring"
	KindUnexpectedBinary AnomalyKind = "unexpected_binary"
	KindBinaryTampering  AnomalyKind = "binary_tampering"
)

type AnomalyEvent struct {
	ID   string      `json:"id"`
	Ts   time.Time   `json:"ts"`
	Kind AnomalyKind `json:"kind"`

	SrcNamespace  string `json:"src_namespace"`
	SrcDeployment string `json:"src_deployment"`
	SrcPod        string `json:"src_pod"`
	SrcNode       string `json:"src_node"`
	SrcProcess    string `json:"src_process"`
	SrcIP         string `json:"src_ip,omitempty"`
	SrcContainer  string `json:"src_container,omitempty"`

	DstIP      string `json:"dst_ip,omitempty"`
	DstPort    uint32 `json:"dst_port,omitempty"`
	DstService string `json:"dst_service,omitempty"`
	DstNS      string `json:"dst_namespace,omitempty"`
	Protocol   string `json:"protocol,omitempty"`

	ScannedPorts []uint32 `json:"scanned_ports,omitempty"`
	PortCount    int      `json:"port_count,omitempty"`
	PortLabel    string   `json:"port_label,omitempty"`
	WindowSec    int      `json:"window_sec,omitempty"`

	Syscall       string `json:"syscall,omitempty"`
	BaselineState string `json:"baseline_state,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type memfdState struct {
	ts  time.Time
	pid string
}

type Notifier interface {
	Notify(ev *AnomalyEvent)
}

type Consumer struct {
	kafka     *kgo.Client
	pool      *pgxpool.Pool
	bcast     *broadcast.Hub
	base      *baseline.Store
	check     *checker.Checker
	recon     *recon.Detector
	enrich    *enricher.Enricher
	fwd       *alertspkg.Forwarder
	processed atomic.Int64
	anomalies atomic.Int64

	lastRecordAt atomic.Int64
	heartbeatOnce sync.Once

	memfdMu   sync.Mutex
	memfdSeen map[string]memfdState
	dedupMu   sync.Mutex
	dedupSeen map[string]time.Time
	debugLogs bool
	ctx       context.Context
	notifier  Notifier
}

func (c *Consumer) SetNotifier(n Notifier) { c.notifier = n }

func (c *Consumer) Close() {
	c.fwd.Close()
}

func New(ctx context.Context, brokers []string, topic string, pool *pgxpool.Pool, base *baseline.Store,
	chk *checker.Checker, enr *enricher.Enricher, bcast *broadcast.Hub) *Consumer {
	kafkaClient, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumerGroup("anomaly-v1"),
		kgo.ConsumeTopics(topic),

		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.AutoCommitInterval(5*time.Second),

		kgo.OnPartitionsAssigned(func(_ context.Context, _ *kgo.Client, assigned map[string][]int32) {
			slog.Info("kafka_partitions_assigned",
				"component", "anomaly-detector/consumer",
				"assigned", assigned)
		}),
		kgo.OnPartitionsRevoked(func(_ context.Context, _ *kgo.Client, revoked map[string][]int32) {
			slog.Info("kafka_partitions_revoked",
				"component", "anomaly-detector/consumer",
				"revoked", revoked)
		}),
	)
	if err != nil {
		log.Fatalf("[consumer] kafka client init: %v", err)
	}
	slog.Info("kafka_consumer_configured",
		"component", "anomaly-detector/consumer",
		"group", "anomaly-v1",
		"brokers", brokers,
		"topic", topic)

	c := &Consumer{
		kafka:     kafkaClient,
		pool:      pool,
		bcast:     bcast,
		base:      base,
		check:     chk,
		recon:     recon.New(),
		enrich:    enr,
		fwd:       alertspkg.NewForwarder(),
		memfdSeen: make(map[string]memfdState),
		dedupSeen: make(map[string]time.Time),
		debugLogs: envBool("ANOMALY_DEBUG_LOGS", false),
		ctx:       ctx,
	}
	go c.cleanupMemfd()
	return c
}

func (c *Consumer) heartbeat(ctx context.Context) {
	const interval = 60 * time.Second
	const silentWarn = 5 * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastProcessed int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			processed := c.processed.Load()
			delta := processed - lastProcessed
			lastProcessed = processed
			lastNano := c.lastRecordAt.Load()
			if lastNano == 0 {
				slog.Info("consumer_heartbeat_no_records",
					"component", "anomaly-detector/consumer",
					"processed", processed,
					"anomalies", c.anomalies.Load())
				continue
			}
			silent := time.Since(time.Unix(0, lastNano))
			if delta == 0 && silent > silentWarn {
				slog.Warn("consumer_heartbeat_silent",
					"component", "anomaly-detector/consumer",
					"silent_for", silent.Truncate(time.Second).String(),
					"processed", processed,
					"anomalies", c.anomalies.Load())
				continue
			}
			slog.Info("consumer_heartbeat",
				"component", "anomaly-detector/consumer",
				"records_delta", delta,
				"interval", interval.String(),
				"processed", processed,
				"anomalies", c.anomalies.Load(),
				"last_record_age", silent.Truncate(time.Second).String())
		}
	}
}

func (c *Consumer) Run(ctx context.Context) error {
	c.heartbeatOnce.Do(func() { go c.heartbeat(ctx) })
	slog.Info("kafka_consumer_started",
		"component", "anomaly-detector/consumer",
		"group", "anomaly-v1")
	for {
		fetches := c.kafka.PollFetches(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errs := fetches.Errors(); len(errs) > 0 {
			for _, e := range errs {
				slog.Warn("kafka_poll_failed",
					"component", "anomaly-detector/consumer",
					"topic", e.Topic,
					"partition", e.Partition,
					"error", e.Err)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		fetches.EachRecord(func(r *kgo.Record) {
			c.processed.Add(1)
			c.lastRecordAt.Store(time.Now().UnixNano())
			extID := fmt.Sprintf("%d:%d", r.Partition, r.Offset)
			for _, a := range c.evaluateRaw(ctx, r.Value) {
				if c.isDuplicate(a) {
					continue
				}
				c.anomalies.Add(1)
				c.emit(ctx, a, extID)
			}
		})
	}
}

func (c *Consumer) Stats() (processed, anomalies int64) {
	return c.processed.Load(), c.anomalies.Load()
}
