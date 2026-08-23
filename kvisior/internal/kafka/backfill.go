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
	"github.com/wolfee-watcher/kvisior/internal/events"
	"github.com/wolfee-watcher/kvisior/internal/podwatch"
	"github.com/wolfee-watcher/kvisior/internal/rules"
)

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
			if !rules.IsBinaryExec(sc) {
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

func eventKindFromMap(ev map[string]interface{}, sc string) events.Kind {
	if raw, ok := ev["event_kind"].(string); ok && raw != "" {
		return events.Kind(raw)
	}
	return events.KindFor(sc)
}

func WarmWatchRing(ctx context.Context, brokers []string, topic string, mgr *podwatch.Manager) {
	watches := mgr.Watches()
	if len(watches) == 0 {
		return
	}

	type podMeta struct {
		selected map[string]bool
		since    time.Time
	}
	podMap := make(map[string]podMeta, len(watches))
	earliest := time.Now()
	for key, snap := range watches {
		m := make(map[string]bool, len(snap.Syscalls)+len(snap.LSMHooks)+len(snap.Tracepoints))
		for _, sc := range snap.Syscalls {
			m[string(events.Syscall)+"/"+sc] = true
		}
		for _, sc := range snap.LSMHooks {
			m[string(events.LSMHook)+"/"+sc] = true
		}
		for _, sc := range snap.Tracepoints {
			m[string(events.Tracepoint)+"/"+sc] = true
		}
		podMap[key] = podMeta{selected: m, since: snap.Since}
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
			podUID, _ := ev["pod_uid"].(string)
			if podUID == "" {
				podUID, _ = ev["podUID"].(string)
			}
			sc, _ := ev["syscall"].(string)
			if ns == "" || pod == "" || sc == "" {
				return
			}
			key := ns + "/" + pod
			meta, ok := podMap[key]
			kind := eventKindFromMap(ev, sc)
			if !ok || !meta.selected[string(kind)+"/"+sc] {
				return
			}

			if rec.Timestamp.Before(meta.since) {
				return
			}
			mgr.Add(ns, pod, podUID, kind, sc, json.RawMessage(rec.Value), rec.Timestamp)
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
