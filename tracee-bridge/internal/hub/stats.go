package hub

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kadm"
)

func (h *Hub) Pool() *pgxpool.Pool { return h.pool }

func (h *Hub) logFunnelLoop() {
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	var lastRecv int64
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-tick.C:
			recv := h.cntReceived.Load()
			if recv == lastRecv {
				continue
			}
			lastRecv = recv
			log.Printf("[hub] funnel: received=%d passed=%d dropped=%d deduped=%d sseClients=%d",
				recv, h.cntPassed.Load(), h.cntDropped.Load(), h.cntDedup.Load(), h.ClientCount())
		}
	}
}

func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *Hub) HistoryLen() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.memHistory)
}

func (h *Hub) PGMode() bool        { return h.pool != nil }
func (h *Hub) SSEDrops() int64     { return h.cntSSEDrops.Load() }
func (h *Hub) SSEEvictions() int64 { return h.cntSSEEvict.Load() }
func (h *Hub) DedupSkipped() int64 { return h.cntDedup.Load() }
func (h *Hub) Received() int64     { return h.cntReceived.Load() }
func (h *Hub) Passed() int64       { return h.cntPassed.Load() }
func (h *Hub) HubDropped() int64   { return h.cntDropped.Load() }
func (h *Hub) KafkaTopic() string  { return h.kafkaTopic }

func (h *Hub) KafkaProducerBuffered() (records, bytes int64) {
	if h.producer == nil {
		return 0, 0
	}
	return h.producer.BufferedProduceRecords(), h.producer.BufferedProduceBytes()
}

type KafkaPartitionInfo struct {
	Partition   int32 `json:"partition"`
	Leader      int32 `json:"leader"`
	ISR         int   `json:"isr"`
	Replicas    int   `json:"replicas"`
	LogStart    int64 `json:"log_start"`
	LogEnd      int64 `json:"log_end"`
	Messages    int64 `json:"messages"`
	GroupOffset int64 `json:"group_offset"`
	Lag         int64 `json:"lag"`
}

type KafkaStats struct {
	BrokerCount     int                  `json:"broker_count"`
	ControllerID    int32                `json:"controller_id"`
	PartitionCount  int                  `json:"partition_count"`
	UnderReplicated int                  `json:"under_replicated"`
	Topic           string               `json:"topic"`
	TotalMessages   int64                `json:"total_messages"`
	TotalLag        int64                `json:"total_lag"`
	Partitions      []KafkaPartitionInfo `json:"partitions"`
	Error           string               `json:"error,omitempty"`
}

type PGStats struct {
	Enabled     bool    `json:"enabled"`
	PingMs      float64 `json:"ping_ms"`
	ActiveConns int32   `json:"active_conns"`
	TotalConns  int32   `json:"total_conns"`
	MaxConns    int32   `json:"max_conns"`
	IdleConns   int32   `json:"idle_conns"`
	Error       string  `json:"error,omitempty"`
}

type KafkaAdminResult struct {
	Kafka    KafkaStats `json:"kafka"`
	Postgres PGStats    `json:"postgres"`
	TS       int64      `json:"ts"`
}

func (h *Hub) KafkaAdminStats(ctx context.Context) KafkaAdminResult {
	res := KafkaAdminResult{TS: time.Now().Unix()}
	res.Kafka.Topic = h.kafkaTopic
	if h.producer == nil {
		res.Kafka.Error = "no kafka producer"
		return res
	}
	adm := kadm.NewClient(h.producer)
	mCtx, mCancel := context.WithTimeout(ctx, 5*time.Second)
	defer mCancel()
	meta, err := adm.Metadata(mCtx, h.kafkaTopic)
	if err != nil {
		res.Kafka.Error = err.Error()
		return res
	}
	res.Kafka.BrokerCount = len(meta.Brokers)
	res.Kafka.ControllerID = meta.Controller

	td, ok := meta.Topics[h.kafkaTopic]
	if !ok || td.Err != nil {
		if td.Err != nil {
			res.Kafka.Error = td.Err.Error()
		}
		return res
	}
	res.Kafka.PartitionCount = len(td.Partitions)

	oCtx, oCancel := context.WithTimeout(ctx, 5*time.Second)
	defer oCancel()
	startOffsets, errStart := adm.ListStartOffsets(oCtx, h.kafkaTopic)
	endOffsets, errEnd := adm.ListEndOffsets(oCtx, h.kafkaTopic)

	for p32, pd := range td.Partitions {
		pi := KafkaPartitionInfo{Partition: p32, Leader: pd.Leader, ISR: len(pd.ISR), Replicas: len(pd.Replicas)}
		if len(pd.ISR) < len(pd.Replicas) {
			res.Kafka.UnderReplicated++
		}
		if errStart == nil {
			if lo, exists := startOffsets.Lookup(h.kafkaTopic, p32); exists && lo.Err == nil {
				pi.LogStart = lo.Offset
			}
		}
		if errEnd == nil {
			if lo, exists := endOffsets.Lookup(h.kafkaTopic, p32); exists && lo.Err == nil {
				pi.LogEnd = lo.Offset
				pi.Messages = pi.LogEnd - pi.LogStart
				res.Kafka.TotalMessages += pi.Messages
			}
		}
		res.Kafka.Partitions = append(res.Kafka.Partitions, pi)
	}
	return res
}

func (h *Hub) PGMetrics(ctx context.Context) PGStats {
	pg := PGStats{Enabled: h.pool != nil}
	if h.pool == nil {
		return pg
	}
	stat := h.pool.Stat()
	pg.ActiveConns = stat.AcquiredConns()
	pg.TotalConns = stat.TotalConns()
	pg.MaxConns = stat.MaxConns()
	pg.IdleConns = stat.IdleConns()

	t0 := time.Now()
	pCtx, pCancel := context.WithTimeout(ctx, 2*time.Second)
	defer pCancel()
	if err := h.pool.Ping(pCtx); err != nil {
		pg.Error = err.Error()
	} else {
		pg.PingMs = float64(time.Since(t0).Microseconds()) / 1000.0
	}
	return pg
}
