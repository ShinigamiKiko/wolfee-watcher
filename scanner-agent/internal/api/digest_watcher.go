package api

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

const (
	defaultDigestWatchInterval  = 2 * time.Minute
	defaultDigestWatchMaxImages = 500
)

func digestWatchInterval() time.Duration {
	if v := os.Getenv("DIGEST_WATCH_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 {
			return time.Duration(n) * time.Second
		}
		slog.Warn("invalid_duration_env",
			"component", "scanner-agent/digest-watch",
			"key", "DIGEST_WATCH_INTERVAL",
			"value", v,
			"default", defaultDigestWatchInterval.String())
	}
	return defaultDigestWatchInterval
}

func digestWatchMaxImages() int {
	v := os.Getenv("DIGEST_WATCH_MAX_IMAGES")
	if v == "" {
		return defaultDigestWatchMaxImages
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		slog.Warn("invalid_int_env",
			"component", "scanner-agent/digest-watch",
			"key", "DIGEST_WATCH_MAX_IMAGES",
			"value", v,
			"default", defaultDigestWatchMaxImages)
		return defaultDigestWatchMaxImages
	}
	return n
}

func (s *Server) digestWatchLoop() {
	interval := digestWatchInterval()
	maxImages := digestWatchMaxImages()
	slog.Info("digest_watch_started",
		"component", "scanner-agent/digest-watch",
		"interval", interval.String(),
		"max_images", maxImages)

	select {
	case <-s.ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}

	s.runDigestCheck()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.runDigestCheck()
		}
	}
}

func (s *Server) runDigestCheck() {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	started := time.Now()

	imgs, err := s.k8s.ListImages(ctx)
	if err != nil {
		slog.Warn("digest_watch_list_images_failed",
			"component", "scanner-agent/digest-watch",
			"error", err)
		return
	}
	if len(imgs) == 0 {
		s.digestCursor = 0
		return
	}

	maxImages := digestWatchMaxImages()
	start := s.digestCursor % len(imgs)
	visited := 0
	checked := 0
	limited := false
	for visited < len(imgs) {
		if ctx.Err() != nil {
			slog.Warn("digest_watch_cycle_timeout",
				"component", "scanner-agent/digest-watch",
				"checked", checked,
				"visited", visited,
				"error", ctx.Err())
			break
		}
		if maxImages > 0 && checked >= maxImages {
			limited = true
			break
		}
		img := imgs[(start+visited)%len(imgs)]
		visited++
		ref := img.Ref
		if ref == "" {
			ref = img.Name
			if img.Tag != "" && img.Tag != "latest" {
				ref += ":" + img.Tag
			}
		}
		if ref == "" || hasPrefix(ref, "sha256:") || isBareSHA(ref) {
			continue
		}
		name := img.Name
		tag := img.Tag
		if name == "" {
			name = ref
		}
		if tag == "" {
			tag = "latest"
		}
		checked++
		s.checkOneDigest(ctx, ref, name, tag, img.Digest)
	}
	s.digestCursor = (start + visited) % len(imgs)
	if limited || s.scanDebugLog {
		slog.Info("digest_watch_cycle_completed",
			"component", "scanner-agent/digest-watch",
			"images", len(imgs),
			"visited", visited,
			"checked", checked,
			"max_images", maxImages,
			"limited", limited,
			"duration_ms", time.Since(started).Milliseconds())
	}
}

func (s *Server) checkOneDigest(ctx context.Context, ref, name, tag, kubeletDigest string) {
	dCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	digest, err := s.inspector.FetchDigest(dCtx, ref)
	cancel()
	if err != nil || !validDigest(digest) {

		if !validDigest(kubeletDigest) {
			return
		}
		digest = kubeletDigest
	}

	base, exists := s.baselines.Get(name, tag)
	if !exists {

		s.baselines.Set(name, tag, digest)
		return
	}
	if base.Digest == digest {
		return
	}

	prevDigest := base.Digest
	now := time.Now()

	s.mu.Lock()
	if res, ok := s.results[ref]; ok {
		if res.Digest == digest && res.DigestChanged && res.DigestChangedAt != nil {
			s.mu.Unlock()
			return
		}
		res.Digest = digest
		res.DigestChanged = true
		res.PreviousDigest = prevDigest
		res.DigestChangedAt = &now
	} else {

		s.results[ref] = &internal.ScanResult{
			Image:           ref,
			Name:            name,
			Tag:             tag,
			Digest:          digest,
			DigestChanged:   true,
			PreviousDigest:  prevDigest,
			DigestChangedAt: &now,
			Status:          internal.StatusDone,
			ScannedAt:       now,
		}
	}
	cp := *s.results[ref]
	s.mu.Unlock()
	s.kv.PushResult(&cp)

	slog.Warn("image_digest_changed",
		"component", "scanner-agent/digest-watch",
		"image", ref,
		"previous_digest_prefix", prevDigest[:min19(prevDigest)],
		"current_digest_prefix", digest[:min19(digest)])

	short := func(d string) string {
		if len(d) > 19 {
			return d[7:19]
		}
		return d
	}
	s.broadcast(internal.ScanEvent{
		Type:    "digest_change",
		Image:   ref,
		Message: fmt.Sprintf("Digest changed: %s…→%s…", short(prevDigest), short(digest)),
		Result:  &cp,
	})
}

func min19(s string) int {
	if len(s) < 19 {
		return len(s)
	}
	return 19
}
