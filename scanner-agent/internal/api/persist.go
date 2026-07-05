package api

import (
	"log"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

func (s *Server) loadSnapshots() {
	var sched internal.ScanSchedule
	if s.kv.PullScannerState("schedule", &sched) {
		sched.NextRun = computeNextRun(sched)
		s.schedMu.Lock()
		s.schedule = sched
		s.schedMu.Unlock()
		log.Printf("[state] restored schedule from kvisior (enabled=%v freq=%s)", sched.Enabled, sched.Frequency)
	}
}

func (s *Server) snapshotHistories() {
	s.histMu.RLock()
	list := make([]internal.ImageHistory, 0, len(s.histories))
	for _, h := range s.histories {
		list = append(list, *h)
	}
	s.histMu.RUnlock()
	s.kv.PushHistories(list)
}

func (s *Server) snapshotSchedule() {
	s.schedMu.RLock()
	sched := s.schedule
	s.schedMu.RUnlock()
	s.kv.PushScannerState("schedule", sched)
}
