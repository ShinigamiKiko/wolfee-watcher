package api

import (
	"context"
	"log"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

func (s *Server) scheduleLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}

		s.schedMu.RLock()
		sched := s.schedule
		s.schedMu.RUnlock()

		if !sched.Enabled || sched.NextRun == nil || time.Now().UTC().Before(*sched.NextRun) {
			continue
		}

		log.Printf("[schedule] triggering scheduled scan (freq=%s time=%s)", sched.Frequency, sched.TimeOfDay)

		now := time.Now().UTC()
		s.schedMu.Lock()
		s.schedule.LastRun = &now
		s.schedule.NextRun = computeNextRun(s.schedule)
		s.schedMu.Unlock()
		s.snapshotSchedule()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		imgs, err := s.k8s.ListImages(ctx)
		cancel()
		if err != nil {
			log.Printf("[schedule] list images error: %v", err)
			continue
		}
		var refs []string
		for _, img := range imgs {
			if img.Ref != "" && !hasPrefix(img.Ref, "sha256:") {
				refs = append(refs, img.Ref)
			}
		}
		if len(refs) > 0 {
			queued := s.enqueueScan(refs)
			log.Printf("[schedule] queued %d/%d images", queued, len(refs))
		}
	}
}

func computeNextRun(s internal.ScanSchedule) *time.Time {
	if !s.Enabled || s.TimeOfDay == "" {
		return nil
	}
	t, err := time.Parse("15:04", s.TimeOfDay)
	if err != nil {
		return nil
	}

	now := time.Now().UTC()
	candidate := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)

	switch s.Frequency {
	case internal.FreqDaily:
		if !candidate.After(now) {
			candidate = candidate.Add(24 * time.Hour)
		}
	case internal.FreqWeekly:
		for i := 0; i <= 7; i++ {
			d := candidate.AddDate(0, 0, i)
			if int(d.Weekday()) == s.DayOfWeek && d.After(now) {
				candidate = d
				break
			}
		}
	default:
		return nil
	}
	return &candidate
}
