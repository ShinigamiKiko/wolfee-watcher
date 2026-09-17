package consumer

import (
	"context"
	"fmt"
	"github.com/wolfee-watcher/pkg/mtls"
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
	EventKind     string `json:"event_kind,omitempty"`
	BaselineState string `json:"baseline_state,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type memfdState struct {
	ts  time.Time
	pid string
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

	emitFailures    atomic.Int64
	alertsPersisted atomic.Int64
	alertsLost      atomic.Int64

	lastRecordAt  atomic.Int64
	heartbeatOnce sync.Once

	memfdMu   sync.Mutex
	memfdSeen map[string]memfdState
	dedupMu   sync.Mutex
	dedupSeen map[string]time.Time
	debugLogs bool
	ctx       context.Context
}

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
		kgo.DisableAutoCommit(),

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
	c.fwd.OnDeliveryFailed(c.persistAlertBatch)
	go c.cleanupMemfd()
	return c
}

func (c *Consumer) persistAlertBatch(batch []alertspkg.AlertLog) {
	if c.pool == nil {
		slog.Error("alert_fallback_unavailable",
			"component", "anomaly-detector/consumer",
			"alerts", len(batch),
			"reason", "no_database_pool")
		return
	}
	for i := range batch {
		al := batch[i]
		ts := al.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := c.pool.Exec(ctx, `
			INSERT INTO alerts
			  (cluster_id, ts, source, det_type, rule_id, rule_name, severity, namespace, target, syscall, detail, fingerprint, data)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			mtls.ClusterID(), ts, al.Source, al.DetType, al.RuleID, al.RuleName, al.Severity, al.Namespace,
			al.Target, al.Syscall, al.Detail, al.Fingerprint, al.Data)
		cancel()
		if err != nil {
			c.alertsLost.Add(1)
			slog.Error("alert_fallback_persist_failed",
				"component", "anomaly-detector/consumer",
				"rule", al.RuleName,
				"namespace", al.Namespace,
				"target", al.Target,
				"error", err)
			continue
		}
		c.alertsPersisted.Add(1)
	}
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
		var processErr error
		fetches.EachRecord(func(r *kgo.Record) {
			if processErr != nil {
				return
			}
			c.processed.Add(1)
			c.lastRecordAt.Store(time.Now().UnixNano())
			extID := fmt.Sprintf("%d:%d", r.Partition, r.Offset)
			for i, a := range c.evaluateRaw(ctx, r.Value) {
				if c.isDuplicate(a) {
					continue
				}
				if err := c.emit(ctx, a, fmt.Sprintf("%s:%d", extID, i)); err != nil {
					c.emitFailures.Add(1)
					processErr = fmt.Errorf("partition %d offset %d: %w", r.Partition, r.Offset, err)
					return
				}
				c.markEmitted(a)
				c.anomalies.Add(1)
			}
		})

		if processErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Error("anomaly_persist_failed",
				"component", "anomaly-detector/consumer",
				"action", "leave_offsets_uncommitted",
				"emit_failures", c.emitFailures.Load(),
				"error", processErr)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}

		if err := c.kafka.CommitUncommittedOffsets(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("offset_commit_failed",
				"component", "anomaly-detector/consumer",
				"error", err)
		}
	}
}

func (c *Consumer) Stats() (processed, anomalies int64) {
	return c.processed.Load(), c.anomalies.Load()
}

func (c *Consumer) DeliveryStats() (emitFailures, alertsPersisted, alertsLost int64) {
	return c.emitFailures.Load(), c.alertsPersisted.Load(), c.alertsLost.Load()
}
