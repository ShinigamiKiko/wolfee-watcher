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
	consumerGroup     = "kvisior-tracee"
	rulesRefreshEvery = 30 * time.Second
)

type Consumer struct {
	client  *kgo.Client
	pub     hub.Publisher
	matcher *rules.Matcher
	store   *store.Store

	debugLogs        bool
	rulesLoaded      atomic.Bool
	lastSyscallRules atomic.Int64
	lastTotalRules   atomic.Int64
}

func New(brokers []string, topic string, pub hub.Publisher, m *rules.Matcher, st *store.Store) (*Consumer, error) {
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
		debugLogs: envBool("KVISIOR_KAFKA_DEBUG_LOGS", false),
	}, nil
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
				return
			}
			sc, _ := ev["syscall"].(string)

			forensic := captureForForensics(sc)
			if ring != nil && forensic {
				ring.Add(raw, eventTime(ev))
			}

			if pw != nil {
				ns, _ := ev["namespace"].(string)
				pod, _ := ev["pod"].(string)
				if sc != "" && pw.ShouldCapture(ns, pod, sc) {
					pw.Add(ns, pod, sc, json.RawMessage(raw), eventTime(ev))
				}
			}

			if forensic || (m != nil && m.AllowsSyscall(sc)) {
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
		return nil
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
		ns, _ := ev["namespace"].(string)
		pod, _ := ev["pod"].(string)
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

func (c *Consumer) refreshRules(ctx context.Context) {
	if c.store == nil {
		return
	}
	rCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := c.store.LoadRules(rCtx)
	if err != nil {
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
