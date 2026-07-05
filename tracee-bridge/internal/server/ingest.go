package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
	"github.com/wolfee-watcher/tracee-bridge/internal/payload"
)

func (s *Server) handleTracee(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		s.recordIngestLatencyMs(elapsed.Milliseconds())
		s.ingestLatencyNanos.Add(elapsed.Nanoseconds())
		s.ingestReqs.Add(1)
	}()

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodeName := r.URL.Query().Get("node")
	defer r.Body.Close()

	events, err := payload.ParseTraceePayloadStream(r.Body, 1<<20)
	if err != nil {
		slog.Warn("tracee_payload_parse_failed",
			"component", "tracee-bridge/ingest",
			"node", nodeName,
			"error", err)
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	s.eventsTotal.Add(int64(len(events)))

	enqueued := 0
	overflowed := 0
	for _, te := range events {
		ui := mapper.Map(te)
		if ui == nil {
			continue
		}
		item := queueItem{ev: ui, nodeName: nodeName, rawCtxID: te.ContainerID}
		select {
		case s.eventQueue <- item:
			enqueued++
		default:
			s.hub.Broadcast(item.ev)
			overflowed++
		}
	}

	if overflowed > 0 {
		s.eventsOverflow.Add(int64(overflowed))
		total := s.eventsOverflow.Load()
		if total%1000 == 0 || total < 10 {
			slog.Warn("ingest_queue_full",
				"component", "tracee-bridge/ingest",
				"node", nodeName,
				"overflowed", overflowed,
				"overflow_total", total,
				"queue_depth", len(s.eventQueue),
				"queue_capacity", cap(s.eventQueue),
				"action", "bypassed_enrichment")
		}
	}

	if s.debugLogs {
		slog.Info("tracee_events_received",
			"component", "tracee-bridge/ingest",
			"node", nodeName,
			"events", len(events),
			"enqueued", enqueued,
			"overflowed", overflowed,
			"queue_depth", len(s.eventQueue))
	}
	w.WriteHeader(http.StatusOK)
}
