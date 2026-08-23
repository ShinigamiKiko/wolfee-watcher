package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/wolfee-watcher/kvisior/internal/binring"
	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/podwatch"
	"github.com/wolfee-watcher/kvisior/internal/rules"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

const (
	consumerGroup        = "kvisior-tracee"
	rulesRefreshEvery    = 30 * time.Second
	rulesStaleWarnAfter  = 5 * time.Minute
	liveMalformedLogName = "live_consumer"
)

type Consumer struct {
	client  *kgo.Client
	pub     hub.Publisher
	matcher *rules.Matcher
	store   *store.Store
	watch   *podwatch.Manager

	debugLogs        bool
	rulesLoaded      atomic.Bool
	lastSyscallRules atomic.Int64
	lastTotalRules   atomic.Int64
	lastRulesOK      atomic.Int64

	dlqTopic     string
	malformed    atomic.Int64
	dlqDelivered atomic.Int64
	dlqFailed    atomic.Int64
	lastMalfLog  atomic.Int64
}

func New(brokers []string, topic string, pub hub.Publisher, m *rules.Matcher, st *store.Store, watch *podwatch.Manager) (*Consumer, error) {
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumerGroup(consumerGroup),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.DisableAutoCommit(),
	)
	if err != nil {
		return nil, fmt.Errorf("kafka consumer: %w", err)
	}
	return &Consumer{
		client:    cl,
		pub:       pub,
		matcher:   m,
		store:     st,
		watch:     watch,
		debugLogs: envBool("KVISIOR_KAFKA_DEBUG_LOGS", false),
		dlqTopic:  os.Getenv("KAFKA_DLQ_TOPIC"),
	}, nil
}

func (c *Consumer) reportMalformed(ctx context.Context, raw []byte, source string) {
	total := c.malformed.Add(1)
	c.quarantine(ctx, raw, source)

	now := time.Now()
	last := c.lastMalfLog.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < time.Minute {
		return
	}
	if !c.lastMalfLog.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	preview := raw
	if len(preview) > 256 {
		preview = preview[:256]
	}
	slog.Error("malformed_event_skipped",
		"component", "kvisior/kafka",
		"source", source,
		"malformed_total", total,
		"dlq_topic", c.dlqTopic,
		"bytes", len(raw),
		"preview", string(preview))
}

func (c *Consumer) quarantine(ctx context.Context, raw []byte, source string) {
	if c.dlqTopic == "" || c.client == nil {
		return
	}
	rec := &kgo.Record{
		Topic: c.dlqTopic,
		Value: raw,
		Headers: []kgo.RecordHeader{
			{Key: "reason", Value: []byte("malformed_json")},
			{Key: "source", Value: []byte(source)},
		},
	}
	c.client.Produce(ctx, rec, func(_ *kgo.Record, err error) {
		if err != nil {
			c.dlqFailed.Add(1)
			return
		}
		c.dlqDelivered.Add(1)
	})
}

var (
	liveMalformed   atomic.Int64
	liveMalfLogLast atomic.Int64
)

func reportLiveMalformed(raw []byte) {
	total := liveMalformed.Add(1)
	now := time.Now()
	last := liveMalfLogLast.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < time.Minute {
		return
	}
	if !liveMalfLogLast.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	preview := raw
	if len(preview) > 256 {
		preview = preview[:256]
	}
	slog.Error("malformed_event_skipped",
		"component", "kvisior/kafka-live",
		"source", liveMalformedLogName,
		"malformed_total", total,
		"bytes", len(raw),
		"preview", string(preview))
}

func LiveMalformedCount() int64 { return liveMalformed.Load() }

func (c *Consumer) MalformedStats() (malformed, dlqDelivered, dlqFailed int64) {
	return c.malformed.Load(), c.dlqDelivered.Load(), c.dlqFailed.Load()
}

func (c *Consumer) RulesStaleFor() time.Duration {
	last := c.lastRulesOK.Load()
	if last == 0 {
		return 0
	}
	return time.Since(time.Unix(0, last))
}

func RunLive(ctx context.Context, brokers []string, topic string, h *hub.Hub, ring *binring.Ring, pw *podwatch.Manager, m *rules.Matcher) {
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtEnd()),
	)
	if err != nil {
		slog.Warn("live_consumer_init_failed",
			"component", "kvisior/kafka-live",
			"topic", topic,
			"error", err,
			"live_feed_enabled", false)
		return
	}
	defer cl.Close()
	for {
		if ctx.Err() != nil {
			return
		}
		fetches := cl.PollFetches(ctx)
		for _, fe := range fetches.Errors() {
			if ctx.Err() == nil {
				slog.Warn("live_consumer_poll_failed",
					"component", "kvisior/kafka-live",
					"topic", fe.Topic,
					"partition", fe.Partition,
					"error", fe.Err)
			}
		}
		fetches.EachRecord(func(r *kgo.Record) {
			raw := r.Value
			var ev map[string]interface{}
			if json.Unmarshal(raw, &ev) != nil {
				reportLiveMalformed(raw)
				return
			}
			sc, _ := ev["syscall"].(string)
			kind := eventKindFromMap(ev, sc)
			ns, _ := ev["namespace"].(string)
			pod, _ := ev["pod"].(string)

			binary := rules.IsBinaryExec(sc)
			watched := pw != nil && sc != "" && pw.ShouldCapture(ns, pod, kind, sc)
			if ring != nil && binary {
				ring.Add(raw, eventTime(ev))
			}

			if pw != nil {
				podUID, _ := ev["pod_uid"].(string)
				if podUID == "" {
					podUID, _ = ev["podUID"].(string)
				}
				if watched {
					pw.Add(ns, pod, podUID, kind, sc, json.RawMessage(raw), eventTime(ev))
				}
			}

			if binary || watched || (m != nil && m.AllowsSyscall(sc)) {
				h.Publish(hub.Event{Type: "tracee_event", Data: json.RawMessage(raw)})
			}
		})
	}
}

func (c *Consumer) Run(ctx context.Context) {
	rulesTick := time.NewTicker(rulesRefreshEvery)
	defer rulesTick.Stop()
	defer c.client.Close()

	c.refreshRules(ctx)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-rulesTick.C:
				c.refreshRules(ctx)
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		fetches := c.client.PollFetches(ctx)
		if errs := fetches.Errors(); len(errs) > 0 {
			for _, e := range errs {
				if ctx.Err() == nil {
					slog.Warn("consumer_poll_failed",
						"component", "kvisior/kafka",
						"topic", e.Topic,
						"partition", e.Partition,
						"error", e.Err)
				}
			}
		}

		var processErr error
		fetches.EachRecord(func(r *kgo.Record) {
			if processErr != nil {
				return
			}
			if err := c.processRecord(ctx, r.Value); err != nil {
				processErr = err
			}
		})
		if processErr != nil {
			slog.Error("record_processing_failed",
				"component", "kvisior/kafka",
				"action", "leave_offsets_uncommitted",
				"error", processErr)
			continue
		}

		if err := c.client.CommitUncommittedOffsets(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("offset_commit_failed",
				"component", "kvisior/kafka",
				"error", err)
		}
	}
}

type sysViolSSE struct {
	rules.Violation
	Fingerprint string `json:"fingerprint"`
}

func (c *Consumer) processRecord(ctx context.Context, raw []byte) error {
	var ev map[string]interface{}
	if json.Unmarshal(raw, &ev) != nil {
		c.reportMalformed(ctx, raw, "policy_consumer")
		return nil
	}
	sc := stringField(ev, "syscall")
	ns := stringField(ev, "namespace")
	pod := stringField(ev, "pod")
	watched := c.watch != nil && ns != "" && pod != "" && c.watch.ShouldCapture(ns, pod, eventKindFromMap(ev, sc), sc)
	if shouldPersistRuntimeEvent(sc, watched) && c.store != nil {
		wCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := c.store.InsertBinaryExecEvent(wCtx, json.RawMessage(raw))
		cancel()
		if err != nil {
			return fmt.Errorf("write binary event: %w", err)
		}
	}

	matches := c.matcher.Match(ev)
	if c.debugLogs && len(matches) > 0 {
		slog.Info("rule_matches_found",
			"component", "kvisior/kafka",
			"matches", len(matches),
			"namespace", ev["namespace"],
			"pod", ev["pod"])
	}
	for _, v := range matches {
		evTs := eventTime(ev)
		fp := store.Fingerprint(v.RuleID, ns, pod, evTs)

		ruleID, ruleName, sev := v.RuleID, v.Rule, v.Sev
		rawCopy := append(json.RawMessage(nil), raw...)
		if c.store != nil {
			wCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.store.WriteViolationChecked(wCtx, "syscall", ruleID, ruleName, sev, ns, pod, fp, rawCopy)
			cancel()
			if err != nil {
				return fmt.Errorf("write violation rule=%s ns=%s pod=%s: %w", ruleID, ns, pod, err)
			}
		}

		sseData, _ := json.Marshal(sysViolSSE{Violation: v, Fingerprint: fp})
		c.pub.Publish(hub.Event{Type: "violation", Data: sseData})
	}
	return nil
}

func shouldPersistRuntimeEvent(syscall string, watched bool) bool {
	return rules.IsBinaryExec(syscall) || watched
}

func stringField(ev map[string]interface{}, key string) string {
	value, _ := ev[key].(string)
	return value
}

func (c *Consumer) refreshRules(ctx context.Context) {
	if c.store == nil {
		return
	}
	rCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := c.store.LoadRules(rCtx)
	if err != nil {
		stale := c.RulesStaleFor()
		if stale >= rulesStaleWarnAfter {
			slog.Error("policy_snapshot_stale",
				"component", "kvisior/kafka",
				"stale_for", stale.Truncate(time.Second).String(),
				"syscall_rules", c.lastSyscallRules.Load(),
				"error", err,
				"impact", "disabled_or_deleted_policies_still_enforced")
			return
		}
		slog.Warn("rules_load_failed",
			"component", "kvisior/kafka",
			"error", err)
		return
	}

	var syscallRules []rules.Rule
	for _, r := range rows {
		var base struct {
			DetType string `json:"detType"`
		}
		if json.Unmarshal(r.Data, &base) != nil {
			continue
		}
		switch base.DetType {
		case "Syscall", "Binary", "LSM", "Tracepoint", "":
			var rule rules.Rule
			if json.Unmarshal(r.Data, &rule) == nil {
				syscallRules = append(syscallRules, rule)
			}
		}
	}
	c.matcher.Replace(syscallRules)
	c.lastRulesOK.Store(time.Now().UnixNano())
	firstLoad := !c.rulesLoaded.Swap(true)
	prevSyscall := c.lastSyscallRules.Swap(int64(len(syscallRules)))
	prevTotal := c.lastTotalRules.Swap(int64(len(rows)))
	changed := prevSyscall != int64(len(syscallRules)) || prevTotal != int64(len(rows))
	if firstLoad || changed || c.debugLogs {
		slog.Info("rules_refreshed",
			"component", "kvisior/kafka",
			"syscall_rules", len(syscallRules),
			"total_policies", len(rows),
			"changed", changed)
	}
}

func eventTime(ev map[string]interface{}) time.Time {
	switch v := ev["ts"].(type) {
	case string:
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
	case float64:
		return time.Unix(int64(v), 0)
	}
	return time.Now()
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		slog.Warn("invalid_bool_env",
			"component", "kvisior/kafka",
			"key", key,
			"value", v,
			"default", def)
		return def
	}
	return b
}
