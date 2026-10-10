package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wolfee-watcher/sensor/internal/logstore"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const maxPodLogBytes = 4 << 20

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

const maxKubeletTailLines = 10000

func (s *Server) tryServeLogsFromStore(w http.ResponseWriter, r *http.Request, ns, name, container string, previous bool, sinceSeconds int64) bool {
	if s.ls == nil || previous || sinceSeconds <= 0 {
		return false
	}
	lines, truncated, err := s.ls.Get(r.Context(), ns, name, container, sinceSeconds)
	if err != nil {
		log.Printf("[sensor] logstore.Get %s/%s/%s: %v — falling back to kubelet", ns, name, container, err)
		return false
	}
	if len(lines) == 0 {
		return false
	}
	lines = append(lines, s.freshKubeletLines(r.Context(), ns, name, container, lines[len(lines)-1].Timestamp)...)
	kept, cut := keepNewestWithin(lines, maxPodLogBytes)
	rawLines := make([]string, 0, len(kept))
	for _, l := range kept {
		text := l.Log
		if l.Timestamp != "" {
			text = l.Timestamp + " " + text
		}
		rawLines = append(rawLines, text)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"namespace": ns,
		"pod":       name,
		"container": container,
		"source":    "postgres",
		"lines":     kept,
		"logs":      strings.Join(rawLines, "\n"),
		"truncated": truncated || cut,
		"fetchedAt": time.Now().UTC().Format(time.RFC3339Nano),
	})
	return true
}

func (s *Server) freshKubeletLines(ctx context.Context, ns, name, container, lastTS string) []logstore.LogLine {
	last, err := time.Parse(time.RFC3339Nano, lastTS)
	if err != nil || s.client == nil {
		return nil
	}
	since := metav1.NewTime(last)
	opts := &corev1.PodLogOptions{Container: container, Timestamps: true, SinceTime: &since}
	opCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream, err := s.client.CoreV1().Pods(ns).GetLogs(name, opts).Stream(opCtx)
	if err != nil {
		return nil
	}
	defer stream.Close()
	var out []logstore.LogLine
	sc := bufio.NewScanner(io.LimitReader(stream, maxPodLogBytes))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		ts, msg, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil || !t.After(last) || strings.TrimSpace(msg) == "" {
			continue
		}
		out = append(out, logstore.LogLine{Timestamp: t.UTC().Format(time.RFC3339Nano), Log: msg})
	}
	return out
}

func keepNewestWithin(lines []logstore.LogLine, limit int) ([]logstore.LogLine, bool) {
	total := 0
	start := len(lines)
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i].Log == "" {
			continue
		}
		size := len(lines[i].Log) + len(lines[i].Timestamp) + 2
		if total+size > limit {
			break
		}
		total += size
		start = i
	}
	out := make([]logstore.LogLine, 0, len(lines)-start)
	for _, l := range lines[start:] {
		if l.Log != "" {
			out = append(out, l)
		}
	}
	return out, start > 0
}

func tailWithin(raw []byte, limit int) ([]byte, bool) {
	if len(raw) <= limit {
		return raw, false
	}
	cut := raw[len(raw)-limit:]
	if i := bytes.IndexByte(cut, '\n'); i >= 0 {
		cut = cut[i+1:]
	}
	return cut, true
}

func (s *Server) serveLogsFromKubelet(w http.ResponseWriter, r *http.Request, ns, name, container string, previous bool, sinceSeconds int64) {
	opts := &corev1.PodLogOptions{Previous: previous}
	if container != "" {
		opts.Container = container
	}
	applyLogTimeFilters(r, opts, sinceSeconds)
	if opts.TailLines == nil && (opts.SinceSeconds != nil || opts.SinceTime != nil) {
		tail := int64(maxKubeletTailLines)
		opts.TailLines = &tail
	}
	stream, err := s.client.CoreV1().Pods(ns).GetLogs(name, opts).Stream(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	defer stream.Close()
	raw, err := io.ReadAll(io.LimitReader(stream, 4*maxPodLogBytes))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	raw, truncated := tailWithin(raw, maxPodLogBytes)
	json.NewEncoder(w).Encode(map[string]any{
		"namespace": ns,
		"pod":       name,
		"container": container,
		"source":    "kubelet",
		"logs":      string(raw),
		"truncated": truncated,
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
