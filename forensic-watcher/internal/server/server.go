package server

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wolfee-watcher/forensic-watcher/internal/fswatch"
	"github.com/wolfee-watcher/pkg/mtls"
)

type Server struct {
	addr       string
	watcher    *fswatch.Watcher
	nodeName   string
	reqTotal   atomic.Int64
	reqErrors  atomic.Int64
	reqLatency atomic.Int64
	debugLogs  bool
	started    time.Time
}

func New(addr string, watcher *fswatch.Watcher, nodeName string) *Server {
	return &Server{
		addr:      addr,
		watcher:   watcher,
		nodeName:  nodeName,
		debugLogs: envBool("FORENSIC_DEBUG_LOGS", false),
		started:   time.Now(),
	}
}

func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":       true,
			"node":     s.nodeName,
			"watching": s.watcher.ActiveWatches(),
		})
	})
	mux.HandleFunc("/stats", s.handleStats)

	mux.HandleFunc("/watch/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		ns, pod, ok := parsePath(r.URL.Path, "/watch/")
		if !ok {
			http.Error(w, "use /watch/{ns}/{pod}", http.StatusBadRequest)
			return
		}
		log.Printf("[forensic] START watch ns=%s pod=%s", ns, pod)
		if err := s.watcher.StartWatch(r.Context(), ns, pod, r.URL.Query().Get("source")); err != nil {
			log.Printf("[forensic] START watch error ns=%s pod=%s: %v", ns, pod, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(watchErrorStatus(err))
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
		log.Printf("[forensic] watching ns=%s pod=%s node=%s", ns, pod, s.nodeName)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":   true,
			"pod":  pod,
			"ns":   ns,
			"node": s.nodeName,
		})
	})

	mux.HandleFunc("/unwatch/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "DELETE required", http.StatusMethodNotAllowed)
			return
		}
		ns, pod, ok := parsePath(r.URL.Path, "/unwatch/")
		if !ok {
			http.Error(w, "use /unwatch/{ns}/{pod}", http.StatusBadRequest)
			return
		}
		s.watcher.StopWatch(r.Context(), ns, pod)
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	mux.HandleFunc("/diff/", func(w http.ResponseWriter, r *http.Request) {
		ns, pod, ok := parsePath(r.URL.Path, "/diff/")
		if !ok {
			http.Error(w, "use /diff/{ns}/{pod}", http.StatusBadRequest)
			return
		}
		entries, err := s.watcher.GetDiff(r.Context(), ns, pod)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ns":      ns,
			"pod":     pod,
			"node":    s.nodeName,
			"count":   len(entries),
			"entries": entries,
		})
	})

	mux.HandleFunc("/tar/", func(w http.ResponseWriter, r *http.Request) {
		ns, pod, ok := parsePath(r.URL.Path, "/tar/")
		if !ok {
			http.Error(w, "use /tar/{ns}/{pod}", http.StatusBadRequest)
			return
		}

		var upperDir string
		var err error
		log.Printf("[forensic] TAR request ns=%s pod=%s watching=%v", ns, pod, s.watcher.IsWatching(ns, pod))
		if s.watcher.IsWatching(ns, pod) {
			upperDir, err = s.watcher.GetUpperDir(ns, pod)
		} else {
			upperDir, err = s.watcher.FindUpperDir(r.Context(), ns, pod)
		}
		if err != nil {
			log.Printf("[forensic] TAR upperDir error ns=%s pod=%s: %v", ns, pod, err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
		select {
		case tarSlots <- struct{}{}:
			defer func() { <-tarSlots }()
		case <-r.Context().Done():
			return
		}
		plan := planTar(r.Context(), upperDir)
		if plan.err != nil {
			log.Printf("[forensic] TAR refused ns=%s pod=%s: %v", ns, pod, plan.err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(map[string]any{"error": plan.err.Error(), "entries": plan.entries, "bytes": plan.bytes})
			return
		}
		log.Printf("[forensic] TAR streaming upperDir=%s entries=%d bytes=%d deleted=%d", upperDir, plan.entries, plan.bytes, len(plan.deleted))

		filename := fmt.Sprintf("fs-diff-%s-%s-%d.tar.gz", ns, pod, time.Now().Unix())
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

		if err := streamTar(r.Context(), w, upperDir, plan.deleted); err != nil {
			log.Printf("[forensic] TAR stream error ns=%s pod=%s: %v", ns, pod, err)
		} else {
			log.Printf("[forensic] TAR done ns=%s pod=%s", ns, pod)
		}
	})

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":       true,
			"node":     s.nodeName,
			"watching": s.watcher.ActiveWatches(),
		})
	})
	go func() {
		log.Printf("[server] health probe listener on :9091 (plain HTTP)")
		if err := http.ListenAndServe(":9091", healthMux); err != nil {
			log.Printf("[server] health server error: %v", err)
		}
	}()

	log.Printf("[server] listening on %s", s.addr)

	return mtls.ListenAuto(ctx, s.addr,
		mtls.RequireServiceExcept(s.logRequests(mux), []mtls.ServiceType{mtls.Sensor}, "/health"),
		mtls.ForensicWatcher, true)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		dur := time.Since(start)
		s.reqTotal.Add(1)
		s.reqLatency.Add(dur.Nanoseconds())
		if rw.status >= 400 {
			s.reqErrors.Add(1)
		}
		if s.debugLogs || rw.status >= 500 {
			log.Printf("[forensic] %s %s -> %d (%s)", r.Method, r.URL.Path, rw.status, dur.Round(time.Millisecond))
		}
	})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	total := s.reqTotal.Load()
	avgMs := 0.0
	if total > 0 {
		avgMs = float64(s.reqLatency.Load()) / float64(total) / float64(time.Millisecond)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service":              "forensic-watcher",
		"node":                 s.nodeName,
		"watching":             s.watcher.ActiveWatches(),
		"http_requests_total":  total,
		"http_requests_errors": s.reqErrors.Load(),
		"http_request_avg_ms":  avgMs,
		"uptime":               time.Since(s.started).Round(time.Second).String(),
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rw *statusRecorder) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

var skipDirs = []string{
	"/var/cache/apt/archives",
	"/var/lib/apt/lists",
	"/var/cache/debconf",
}

const maxTarFileBytes = 128 << 20
const maxTarTotalBytes = 512 << 20
const maxTarEntries = 10000
const deletedListName = "WOLFEE-DELETED-FILES.txt"

var tarSlots = make(chan struct{}, 2)

type tarPlan struct {
	entries int
	bytes   int64
	deleted []string
	err     error
}

func watchErrorStatus(err error) int {
	switch {
	case errors.Is(err, fswatch.ErrPodGone):
		return http.StatusNotFound
	case errors.Is(err, fswatch.ErrNotRunning), errors.Is(err, fswatch.ErrOtherNode):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func tarName(upperDir, path string) string {
	return strings.TrimPrefix(strings.TrimPrefix(path, upperDir), "/")
}

func skippedDir(name string) bool {
	for _, skip := range skipDirs {
		skip = strings.TrimPrefix(skip, "/")
		if name == skip || strings.HasPrefix(name, skip+"/") {
			return true
		}
	}
	return false
}

func isWhiteout(info os.FileInfo) bool {
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Rdev == 0
}

func planTar(ctx context.Context, upperDir string) tarPlan {
	var p tarPlan
	p.err = filepath.Walk(upperDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == upperDir {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := tarName(upperDir, path)
		if info.IsDir() && skippedDir(name) {
			return filepath.SkipDir
		}
		if isWhiteout(info) {
			p.deleted = append(p.deleted, "/"+name)
			return nil
		}
		p.entries++
		if p.entries > maxTarEntries {
			return fmt.Errorf("container layer has more than %d entries", maxTarEntries)
		}
		if info.Mode().IsRegular() && info.Size() <= maxTarFileBytes {
			p.bytes += info.Size()
			if p.bytes > maxTarTotalBytes {
				return fmt.Errorf("container layer is larger than %d MiB", maxTarTotalBytes>>20)
			}
		}
		return nil
	})
	return p
}

func streamTar(ctx context.Context, w io.Writer, upperDir string, deleted []string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	walkErr := filepath.Walk(upperDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == upperDir {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		name := tarName(upperDir, path)
		if info.IsDir() {
			if skippedDir(name) {
				return filepath.SkipDir
			}
			return tw.WriteHeader(&tar.Header{
				Name:     name + "/",
				Typeflag: tar.TypeDir,
				Mode:     int64(info.Mode().Perm()),
				ModTime:  info.ModTime(),
			})
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, lerr := os.Readlink(path)
			if lerr != nil {
				return nil
			}
			return tw.WriteHeader(&tar.Header{
				Name:     name,
				Typeflag: tar.TypeSymlink,
				Linkname: target,
				Mode:     int64(info.Mode().Perm()),
				ModTime:  info.ModTime(),
			})
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > maxTarFileBytes {
			log.Printf("[streamTar] skip oversized %s (> %d bytes)", name, maxTarFileBytes)
			return nil
		}
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil
		}
		data, readErr := io.ReadAll(io.LimitReader(f, maxTarFileBytes+1))
		f.Close()
		if readErr != nil {
			log.Printf("[streamTar] read %s: %v", path, readErr)
			return nil
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:    name,
			Size:    int64(len(data)),
			Mode:    int64(info.Mode().Perm()),
			ModTime: info.ModTime(),
		}); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if walkErr == nil && len(deleted) > 0 {
		body := []byte(strings.Join(deleted, "\n") + "\n")
		if err := tw.WriteHeader(&tar.Header{Name: deletedListName, Size: int64(len(body)), Mode: 0o644, ModTime: time.Now()}); err == nil {
			_, walkErr = tw.Write(body)
		} else {
			walkErr = err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("tar close: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}
	return walkErr
}

func parsePath(path, prefix string) (ns, pod string, ok bool) {
	trimmed := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
