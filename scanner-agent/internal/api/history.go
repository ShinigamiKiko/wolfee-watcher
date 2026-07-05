package api

import (
	"context"
	"log"
	"sync"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

func (s *Server) historyLoop() {
	s.fetchAllHistories()
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.fetchAllHistories()
		}
	}
}

func (s *Server) fetchAllHistories() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	imgs, err := s.k8s.ListImages(ctx)
	cancel()
	if err != nil {
		log.Printf("[history] list images error: %v — skipping cycle", err)
		return
	}

	seen := map[string]bool{}
	var refs []string
	for _, img := range imgs {
		ref := img.Ref
		if ref == "" || hasPrefix(ref, "sha256:") || isBareSHA(ref) || hasPrefix(ref, "localhost/") {
			continue
		}
		if !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		log.Printf("[history] no pullable images found")
		return
	}
	log.Printf("[history] checking %d images", len(refs))

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	for _, ref := range refs {
		ref := ref

		s.histMu.RLock()
		existing, ok := s.histories[ref]
		s.histMu.RUnlock()

		if ok && existing.Status == internal.HistoryDone &&
			!existing.Stale &&
			time.Since(existing.FetchedAt) < 14*time.Minute {
			continue
		}

		s.histMu.Lock()
		s.histories[ref] = &internal.ImageHistory{Image: ref, Status: internal.HistoryFetching}
		s.histMu.Unlock()

		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			imgCtx, imgCancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer imgCancel()

			entries, fetchErr := s.inspector.FetchHistory(imgCtx, ref)

			s.histMu.Lock()
			defer s.histMu.Unlock()

			if fetchErr != nil {
				log.Printf("[history] %s: %v", ref, fetchErr)
				if prev, ok := s.histories[ref]; ok && len(prev.Layers) > 0 {
					prev.Status = internal.HistoryUnavailable
					prev.Stale = true
					prev.Error = fetchErr.Error()
				} else {
					s.histories[ref] = &internal.ImageHistory{
						Image:  ref,
						Status: internal.HistoryUnavailable,
						Error:  fetchErr.Error(),
					}
				}
				return
			}

			layers := make([]internal.HistoryLayer, 0, len(entries))
			for _, e := range entries {
				layers = append(layers, internal.HistoryLayer{
					CreatedBy:  e.CreatedBy,
					EmptyLayer: e.EmptyLayer,
				})
			}
			s.histories[ref] = &internal.ImageHistory{
				Image:     ref,
				Status:    internal.HistoryDone,
				FetchedAt: time.Now(),
				Layers:    layers,
			}
			log.Printf("[history] %s: %d layers", ref, len(layers))
		}()
	}

	wg.Wait()

	done, unavail := 0, 0
	s.histMu.RLock()
	for _, h := range s.histories {
		if h.Status == internal.HistoryDone {
			done++
		}
		if h.Status == internal.HistoryUnavailable {
			unavail++
		}
	}
	s.histMu.RUnlock()
	s.snapshotHistories()
	log.Printf("[history] cycle complete — done:%d unavailable:%d", done, unavail)
}
