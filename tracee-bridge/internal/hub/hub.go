package hub

import (
	"context"
	"log"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/wolfee-watcher/tracee-bridge/internal/alerter"
)

const (
	streamMaxMem     = int64(50_000)
	historyReplayCap = int64(10_000)
	chanBuf          = 64
	dedupTTL         = 5 * time.Minute
	defaultMaxDrops  = int32(256)
	pgOpTimeout      = 3 * time.Second
)

var alwaysPass = map[string]bool{
	"connect": true, "bind": true,
	"accept": true, "accept4": true,
	"sendto": true,
	"dup2":   true, "dup3": true,
	"execve": true, "execveat": true, "sched_process_exec": true,
	"ptrace": true, "process_vm_writev": true,
	"memfd_create": true, "bpf": true,
	"socket": true,
	"mmap":   true, "mprotect": true,
	"init_module": true, "finit_module": true, "module_load": true,
	"pivot_root": true, "unshare": true, "setns": true,
	"chroot": true, "mount": true, "umount2": true,
	"security_sb_mount": true,
	"setuid":            true, "setgid": true,
	"setreuid": true, "setresuid": true, "setresgid": true,
	"capset": true,
	"open":   true, "openat": true,
	"io_uring_setup": true, "io_uring_enter": true, "io_uring_register": true,

	"sched_process_fork": true, "sched_process_exit": true,
	"task_rename": true, "sched_switch": true, "module_free": true,
	"cgroup_mkdir": true, "cgroup_rmdir": true, "cgroup_attach_task": true,

	"clone": true, "kill": true, "chdir": true, "openat2": true,

	"security_file_open": true, "security_inode_unlink": true,
	"security_inode_rename": true, "security_inode_symlink": true,
	"security_inode_mknod": true,
	"security_bprm_check":  true, "security_mmap_file": true,
	"security_file_mprotect": true,
	"security_socket_create": true,
	"security_socket_connect": true,
	"security_socket_bind": true,
	"security_socket_accept": true,
	"security_socket_listen": true,
	"security_socket_setsockopt": true,
	"security_bpf": true,
	"security_bpf_map": true,
	"security_kernel_read_file": true,
}

func isLSMHook(sc string) bool {
	return strings.HasPrefix(sc, "security_")
}

type Hub struct {
	mu          sync.RWMutex
	clients     map[*client]struct{}
	memHistory  [][]byte
	dedupMu     sync.Mutex
	dedup       map[string]time.Time
	ctx         context.Context
	producer    *kgo.Client
	sseConsumer *kgo.Client
	kafkaTopic  string
	pool        *pgxpool.Pool

	cntReceived    atomic.Int64
	cntPassed      atomic.Int64
	cntDropped     atomic.Int64
	cntDedup       atomic.Int64
	cntSSEDrops    atomic.Int64
	cntSSEEvict    atomic.Int64
	maxClientDrops int32
	debugLogs      bool

	alerter *alerter.Alerter
}

type client struct {
	ch     chan []byte
	done   chan struct{}
	drops  atomic.Int32
	closed atomic.Bool
}

func newClient(buf int) *client {
	return &client{ch: make(chan []byte, buf), done: make(chan struct{})}
}

func (c *client) close() {
	if c.closed.CompareAndSwap(false, true) {
		close(c.done)
	}
}

type StreamEvent struct {
	ID   string
	Data []byte
}

func New(ctx context.Context, brokers []string, topic string, pgDSN string) *Hub {
	if ctx == nil {
		ctx = context.Background()
	}
	h := &Hub{
		clients:        make(map[*client]struct{}),
		dedup:          make(map[string]time.Time),
		maxClientDrops: int32(envInt("SSE_CLIENT_MAX_DROPS", int(defaultMaxDrops))),
		debugLogs:      envBool("TRACEE_BRIDGE_DEBUG_LOGS", false),
		ctx:            ctx,
		kafkaTopic:     topic,
	}

	producer, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.DefaultProduceTopic(topic),
		kgo.ProducerBatchMaxBytes(1_000_000),
		kgo.RecordDeliveryTimeout(5*time.Second),
		kgo.RequiredAcks(kgo.AllISRAcks()),
	)
	if err != nil {
		log.Fatalf("[hub] kafka producer init: %v", err)
	}
	h.producer = producer
	slog.Info("kafka_producer_connected",
		"component", "tracee-bridge/hub",
		"brokers", brokers,
		"topic", topic,
		"required_acks", "all_isr")

	go func() {
		ctxC, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		adm := kadm.NewClient(producer)
		partitions := int32(envInt("KAFKA_TOPIC_PARTITIONS", 6))
		replicas := int16(envInt("KAFKA_TOPIC_REPLICATION", -1))
		if _, err := adm.CreateTopic(ctxC, partitions, replicas, nil, topic); err != nil {
			if !strings.Contains(err.Error(), "TOPIC_ALREADY_EXISTS") {
				slog.Warn("kafka_topic_ensure_failed",
					"component", "tracee-bridge/hub",
					"topic", topic,
					"partitions", partitions,
					"replication_factor", replicas,
					"error", err)
			}
		}
	}()

	sseConsumer, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtEnd()),
	)
	if err != nil {
		log.Fatalf("[hub] kafka sse consumer init: %v", err)
	}
	h.sseConsumer = sseConsumer
	go h.sseFanOutLoop()
	go h.logFunnelLoop()

	if pgDSN == "" {
		slog.Warn("postgres_dsn_missing",
			"component", "tracee-bridge/hub",
			"mode", "in_memory_history")
		h.alerter = alerter.New(ctx, nil)
		return h
	}
	pool, err := pgxpool.New(ctx, pgDSN)
	if err != nil {
		slog.Warn("postgres_pool_init_failed",
			"component", "tracee-bridge/hub",
			"error", err,
			"history_available", false)
		h.alerter = alerter.New(ctx, nil)
		return h
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		slog.Warn("postgres_unreachable",
			"component", "tracee-bridge/hub",
			"error", err,
			"history_available", false)
		pool.Close()
		h.alerter = alerter.New(ctx, nil)
		return h
	}
	h.pool = pool
	h.alerter = alerter.New(ctx, pool)
	slog.Info("postgres_connected",
		"component", "tracee-bridge/hub",
		"history_available", true)

	return h
}
