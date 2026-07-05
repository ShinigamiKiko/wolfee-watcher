package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/wolfee-watcher/kvisior/internal/binring"
	"github.com/wolfee-watcher/kvisior/internal/podwatch"
	"github.com/wolfee-watcher/kvisior/internal/rules"
)

func captureForForensics(sc string) bool {
	return rules.IsBinaryExec(sc)
}

func BackfillHandler(ring *binring.Ring) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		events := ring.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"events": events}); err != nil {
			log.Printf("[backfill] encode error: %v", err)
			return
		}
		log.Printf("[backfill] served %d binary events from ring", len(events))
	}
}

func WarmRing(ctx context.Context, brokers []string, topic string, ring *binring.Ring) {
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AfterMilli(
			time.Now().Add(-24*time.Hour).UnixMilli(),
		)),
		kgo.FetchMaxWait(time.Second),
	)
	if err != nil {
		log.Printf("[backfill] warm ring: client init: %v", err)
		return
	}
	defer cl.Close()

	wctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	start := time.Now()
	added := 0
	caughtUpAfter := time.Now().Add(-2 * time.Second)

	for {
		if wctx.Err() != nil {
			break
		}
		fetches := cl.PollFetches(wctx)
		if fetches.IsClientClosed() {
			break
		}
		if errs := fetches.Errors(); len(errs) > 0 {
			for _, fe := range errs {
				if !errors.Is(fe.Err, context.Canceled) && !errors.Is(fe.Err, context.DeadlineExceeded) {
					log.Printf("[backfill] warm ring: kafka error: %v", fe.Err)
				}
			}
			break
		}

		empty := true
		done := false
		fetches.EachRecord(func(rec *kgo.Record) {
			empty = false
			var ev map[string]json.RawMessage
			if json.Unmarshal(rec.Value, &ev) != nil {
				return
			}
			var sc string
			if raw, ok := ev["syscall"]; ok {
				json.Unmarshal(raw, &sc)
			}
			if !captureForForensics(sc) {
				return
			}
			ring.Add(rec.Value, rec.Timestamp)
			added++
			if rec.Timestamp.After(caughtUpAfter) {
				done = true
			}
		})

		if empty || done {
			break
		}
	}

	log.Printf("[backfill] warm ring complete: +%d binary events in %s (ring=%d)",
		added, time.Since(start).Round(time.Second), ring.Len())
}

func WarmWatchRing(ctx context.Context, brokers []string, topic string, mgr *podwatch.Manager) {
	watches := mgr.Watches()
	if len(watches) == 0 {
		return
	}

	type podMeta struct {
		syscalls map[string]bool
		since    time.Time
	}
	podMap := make(map[string]podMeta, len(watches))
	earliest := time.Now()
	for key, snap := range watches {
		m := make(map[string]bool, len(snap.Syscalls))
		for _, sc := range snap.Syscalls {
			m[sc] = true
		}
		podMap[key] = podMeta{syscalls: m, since: snap.Since}
		if snap.Since.Before(earliest) {
			earliest = snap.Since
		}
	}

	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AfterMilli(earliest.UnixMilli())),
		kgo.FetchMaxWait(time.Second),
	)
	if err != nil {
		log.Printf("[backfill] warm watch ring: client init: %v", err)
		return
	}
	defer cl.Close()

	wctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	start := time.Now()
	added := 0
	caughtUpAfter := time.Now().Add(-2 * time.Second)

	for {
		if wctx.Err() != nil {
			break
		}
		fetches := cl.PollFetches(wctx)
		if fetches.IsClientClosed() {
			break
		}
		if errs := fetches.Errors(); len(errs) > 0 {
			for _, fe := range errs {
				if !errors.Is(fe.Err, context.Canceled) && !errors.Is(fe.Err, context.DeadlineExceeded) {
					log.Printf("[backfill] warm watch ring: kafka error: %v", fe.Err)
				}
			}
			break
		}

		empty := true
		done := false
		fetches.EachRecord(func(rec *kgo.Record) {
			empty = false
			var ev map[string]interface{}
			if json.Unmarshal(rec.Value, &ev) != nil {
				return
			}
			ns, _ := ev["namespace"].(string)
			pod, _ := ev["pod"].(string)
			sc, _ := ev["syscall"].(string)
			if ns == "" || pod == "" || sc == "" {
				return
			}
			key := ns + "/" + pod
			meta, ok := podMap[key]
			if !ok || !meta.syscalls[sc] {
				return
			}

			if rec.Timestamp.Before(meta.since) {
				return
			}
			mgr.Add(ns, pod, sc, json.RawMessage(rec.Value), rec.Timestamp)
			added++
			if rec.Timestamp.After(caughtUpAfter) {
				done = true
			}
		})

		if empty || done {
			break
		}
	}

	log.Printf("[backfill] warm watch ring complete: +%d syscall events in %s",
		added, time.Since(start).Round(time.Second))
}
