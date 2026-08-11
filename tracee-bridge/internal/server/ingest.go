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
	for _, te := range events {
		ui := mapper.Map(te)
		if ui == nil {
			continue
		}
		item := queueItem{
			ev:       ui,
			nodeName: nodeName,
			rawCtxID: ui.ContainerID,
			hostPID:  te.HostProcessID,
			hostPPID: te.HostParentProcessID,
			hostTID:  te.HostThreadID,
		}
		select {
		case s.eventQueue <- item:
			enqueued++
		case <-r.Context().Done():
			s.eventsBusy.Add(1)
			http.Error(w, "ingest busy; retry", http.StatusServiceUnavailable)
			return
		}
	}

	if s.debugLogs {
		slog.Info("tracee_events_received",
			"component", "tracee-bridge/ingest",
			"node", nodeName,
			"events", len(events),
			"enqueued", enqueued,
			"queue_depth", len(s.eventQueue))
	}
	w.WriteHeader(http.StatusOK)
}
