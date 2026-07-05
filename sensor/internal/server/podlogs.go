package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *Server) handlePodLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/pods/"), "/")
	if len(parts) != 3 || parts[2] != "logs" {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"error": "use /api/pods/{namespace}/{name}/logs"})
		return
	}
	ns, name := parts[0], parts[1]
	q := r.URL.Query()
	container := q.Get("container")
	previous := q.Get("previous") == "true"
	sinceSeconds := parseSinceSeconds(q.Get("sinceSeconds"))

	if s.tryServeLogsFromStore(w, r, ns, name, container, previous, sinceSeconds) {
		return
	}
	s.serveLogsFromKubelet(w, r, ns, name, container, previous, sinceSeconds)
}

func parseSinceSeconds(secStr string) int64 {
	if secStr == "" {
		return 0
	}
	if v, err := strconv.ParseInt(secStr, 10, 64); err == nil && v > 0 {
		return v
	}
	return 0
}

func (s *Server) tryServeLogsFromStore(w http.ResponseWriter, r *http.Request, ns, name, container string, previous bool, sinceSeconds int64) bool {
	if s.ls == nil || previous || sinceSeconds <= 0 {
		return false
	}
	lines, err := s.ls.Get(r.Context(), ns, name, container, sinceSeconds)
	if err != nil {
		log.Printf("[sensor] logstore.Get %s/%s/%s: %v — falling back to kubelet", ns, name, container, err)
		return false
	}
	if len(lines) == 0 {
		return false
	}
	rawLines := make([]string, 0, len(lines))
	for _, l := range lines {
		if l.Log == "" {
			continue
		}
		if l.Timestamp != "" {
			rawLines = append(rawLines, l.Timestamp+" "+l.Log)
		} else {
			rawLines = append(rawLines, l.Log)
		}
	}
	json.NewEncoder(w).Encode(map[string]any{
		"namespace": ns,
		"pod":       name,
		"container": container,
		"source":    "postgres",
		"lines":     lines,
		"logs":      strings.Join(rawLines, "\n"),
		"fetchedAt": time.Now().UTC().Format(time.RFC3339Nano),
	})
	return true
}

func (s *Server) serveLogsFromKubelet(w http.ResponseWriter, r *http.Request, ns, name, container string, previous bool, sinceSeconds int64) {
	opts := &corev1.PodLogOptions{Previous: previous}
	if container != "" {
		opts.Container = container
	}
	applyLogTimeFilters(r, opts, sinceSeconds)
	stream, err := s.client.CoreV1().Pods(ns).GetLogs(name, opts).Stream(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	defer stream.Close()
	raw, err := io.ReadAll(stream)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"namespace": ns,
		"pod":       name,
		"container": container,
		"source":    "kubelet",
		"logs":      string(raw),
		"fetchedAt": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func applyLogTimeFilters(r *http.Request, opts *corev1.PodLogOptions, sinceSeconds int64) {
	q := r.URL.Query()
	if sinceStr := q.Get("sinceTime"); sinceStr != "" {
		t, err := time.Parse(time.RFC3339Nano, sinceStr)
		if err != nil {
			t, err = time.Parse(time.RFC3339, sinceStr)
		}
		if err == nil {
			mt := metav1.NewTime(t)
			opts.SinceTime = &mt
			return
		}
	}
	if sinceSeconds > 0 {
		opts.SinceSeconds = &sinceSeconds
		return
	}
	applyTailFilter(q.Get("tail"), opts, false)
}

func applyTailFilter(tailStr string, opts *corev1.PodLogOptions, previous bool) {
	if tailStr != "" && tailStr != "all" {
		if v, err := strconv.ParseInt(tailStr, 10, 64); err == nil && v > 0 && v <= 10000 {
			opts.TailLines = &v
		}
		return
	}
	if tailStr == "" && !previous {
		tail := int64(500)
		opts.TailLines = &tail
	}
}
