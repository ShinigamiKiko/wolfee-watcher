package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/wolfee-watcher/sensor/internal/collector"
)

func (s *Server) SetSnapshot(snap *collector.Snapshot) {
	raw, err := json.Marshal(snap)
	if err != nil {
		log.Printf("[sensor] snapshot marshal failed: %v", err)
		return
	}
	gz, err := gzipBytes(raw)
	if err != nil {
		log.Printf("[sensor] snapshot gzip failed: %v", err)
		return
	}
	maxMB := envInt("SENSOR_MAX_SNAPSHOT_MB", 0)
	if maxMB > 0 && len(gz) > maxMB*1024*1024 {
		log.Printf("[sensor] snapshot skipped: gzip size=%d exceeds SENSOR_MAX_SNAPSHOT_MB=%d", len(gz), maxMB)
		return
	}

	etag := `"` + snap.CollectedAt.Format("20060102150405") + `"`
	s.mu.Lock()
	s.snapGzip = gz
	s.snapETag = etag
	s.snapStruct = snap
	s.podNode = snapshotPodNode(snap)
	s.podCount = len(snap.Pods)
	s.mu.Unlock()

	s.storeSnapshotInPG(gz, etag)
}

func snapshotPodNode(snap *collector.Snapshot) map[string]string {
	podNode := make(map[string]string, len(snap.Pods))
	for _, p := range snap.Pods {
		podNode[p.Namespace+"/"+p.Name] = p.Spec.NodeName
	}
	return podNode
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	gzSnap := s.snapGzip
	etag := s.snapETag
	s.mu.RUnlock()
	if len(gzSnap) == 0 {
		loadedGz, loadedETag, err := s.loadSnapshotFromPG(r.Context())
		if err != nil || len(loadedGz) == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{"error": "snapshot not ready yet"})
			return
		}
		gzSnap, etag = s.cacheSnapshotFromPG(loadedGz, loadedETag)
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gzSnap)
		return
	}
	raw, err := gunzipBytes(gzSnap)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": "snapshot decode failed"})
		return
	}
	_, _ = w.Write(raw)
}

func (s *Server) cacheSnapshotFromPG(loadedGz []byte, loadedETag string) ([]byte, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapGzip = loadedGz
	s.snapETag = loadedETag
	if raw, err := gunzipBytes(loadedGz); err == nil {
		var snap collector.Snapshot
		if err := json.Unmarshal(raw, &snap); err == nil {
			s.podNode = snapshotPodNode(&snap)
			s.podCount = len(snap.Pods)
		}
	}
	return s.snapGzip, s.snapETag
}

func (s *Server) syncPodNodeFromPG() {
	if s.ls == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	gz, _, err := s.loadSnapshotFromPG(ctx)
	if err != nil || len(gz) == 0 {
		return
	}
	raw, err := gunzipBytes(gz)
	if err != nil {
		return
	}
	var snap collector.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return
	}
	podNode := snapshotPodNode(&snap)
	s.mu.Lock()
	if s.podCount == 0 || len(podNode) >= s.podCount {
		s.podNode = podNode
		s.podCount = len(snap.Pods)
	}
	s.mu.Unlock()
	log.Printf("[sensor] podNode synced from PostgreSQL: %d pods", len(podNode))
}

func (s *Server) storeSnapshotInPG(gz []byte, etag string) {
	if s.ls == nil || len(gz) == 0 || etag == "" {
		return
	}
	if err := s.ls.SetSnapshotCache(s.ctx, gz, etag); err != nil {
		log.Printf("[sensor] kvisior snapshot cache write failed: %v", err)
	}
}

func (s *Server) loadSnapshotFromPG(ctx context.Context) ([]byte, string, error) {
	if s.ls == nil {
		return nil, "", fmt.Errorf("snapshot cache disabled")
	}
	return s.ls.GetSnapshotCache(ctx)
}

func gzipBytes(raw []byte) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(raw); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func gunzipBytes(gzData []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(gzData))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(gz)
}
