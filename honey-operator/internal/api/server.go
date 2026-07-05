package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/wolfee-watcher/pkg/httputil"
	"github.com/wolfee-watcher/honey-operator/internal/k8s"
	"github.com/wolfee-watcher/pkg/mtls"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

var honeypotNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type Server struct {
	addr    string
	ctx     context.Context
	manager *k8s.Manager
	hub     Broadcaster
}

func New(ctx context.Context, addr string, manager *k8s.Manager, hub Broadcaster) *Server {
	return &Server{addr: addr, ctx: ctx, manager: manager, hub: hub}
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("X-Acting-Role")) == "admin" {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"admin role required"}`))
	return false
}

func (s *Server) Run() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", httputil.CORS(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	}))

	mux.HandleFunc("/api/honeypots", httputil.CORS(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleList(w, r)
		case http.MethodPost:
			if !requireAdmin(w, r) {
				return
			}
			s.handleCreate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/honeypots/", httputil.CORS(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/honeypots/")
		parts := strings.SplitN(path, "/", 2)

		if len(parts) == 1 && r.Method == http.MethodDelete {
			if !requireAdmin(w, r) {
				return
			}
			s.handleDelete(w, r, parts[0])
			return
		}
		if len(parts) == 2 && parts[1] == "events" && r.Method == http.MethodGet {
			s.handleEvents(w, r, parts[0])
			return
		}
		if len(parts) == 2 && parts[1] == "logs" && r.Method == http.MethodGet {
			s.handleLogs(w, r, parts[0])
			return
		}
		http.NotFound(w, r)
	}))

	mux.HandleFunc("/api/honeypots/stream", httputil.CORS(s.handleStream))

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	go func() {
		log.Printf("[honey-operator] health probe listener on :9096 (plain HTTP)")
		if err := http.ListenAndServe(":9096", healthMux); err != nil {
			log.Printf("[honey-operator] health probe listener error: %v", err)
		}
	}()

	log.Printf("[honey-operator] listening on %s", s.addr)

	return mtls.ListenAuto(s.ctx, s.addr,
		mtls.RequireServiceExcept(mux, []mtls.ServiceType{mtls.Kvisior}, "/health"),
		mtls.HoneyOperator, true)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("namespace")

	pods, err := s.manager.List(r.Context(), ns)
	if err != nil {
		log.Printf("[honey-operator] LIST ERROR ns=%s err=%v", ns, err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	result := make([]HoneypotStatus, 0, len(pods))
	for _, pod := range pods {

		name := pod.Labels["honeypot-name"]
		if name == "" {

			name = strings.TrimPrefix(pod.Name, "h-")
		}
		var services []string
		for _, c := range pod.Spec.Containers {

			for i, arg := range c.Args {
				if arg == "--setup" && i+1 < len(c.Args) {
					services = strings.Split(c.Args[i+1], ",")
				}
			}
		}

		podNS := pod.Namespace
		ip := ""
		if svc, err := s.manager.GetService(r.Context(), name, podNS); err == nil {
			ip = svc.Spec.ClusterIP
		}

		eventCount := 0

		result = append(result, HoneypotStatus{
			Name:       name,
			Namespace:  pod.Namespace,
			Services:   services,
			ClusterIP:  ip,
			Phase:      string(pod.Status.Phase),
			CreatedAt:  pod.CreationTimestamp.Time,
			EventCount: eventCount,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"honeypots": result,
		"total":     len(result),
	})
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var spec HoneypotSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if spec.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}

	if !honeypotNameRe.MatchString(spec.Name) || len(spec.Name) > 40 {
		writeErr(w, http.StatusBadRequest, `name must be a DNS-1123 label: lowercase letters, digits and "-" (max 40 chars)`)
		return
	}
	if spec.Namespace == "" {
		spec.Namespace = "wolfee-watcher"
	}
	if len(spec.Services) == 0 {
		writeErr(w, http.StatusBadRequest, "at least one service is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	if err := s.manager.CheckNamespace(ctx, spec.Namespace); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("namespace %q not found", spec.Namespace))
		return
	}

	if err := s.manager.Create(ctx, spec.Name, spec.Namespace, spec.Services); err != nil {
		log.Printf("[honey-operator] CREATE ERROR name=%s ns=%s services=%v err=%v", spec.Name, spec.Namespace, spec.Services, err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("[honey-operator] created honeypot %s/%s services=%v",
		spec.Namespace, spec.Name, spec.Services)

	writeJSON(w, http.StatusCreated, map[string]string{
		"name":      spec.Name,
		"namespace": spec.Namespace,
		"status":    "created",
	})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, name string) {
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = "wolfee-watcher"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	if err := s.manager.Delete(ctx, name, ns); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("[honey-operator] deleted honeypot %s/%s", ns, name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, name string) {
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = "wolfee-watcher"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	raw, err := s.manager.Logs(ctx, name, ns, 500)
	if err != nil {
		if isUnavailableLogsErr(err) {
			writeJSON(w, http.StatusOK, HoneypotEventsResponse{
				Name:   name,
				Events: []HoneypotEvent{},
				Total:  0,
			})
			return
		}
		log.Printf("[honey-operator] EVENTS ERROR ns=%s name=%s err=%v", ns, name, err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	events := ParseLogs(raw)
	writeJSON(w, http.StatusOK, HoneypotEventsResponse{
		Name:   name,
		Events: events,
		Total:  len(events),
	})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request, name string) {
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = "wolfee-watcher"
	}

	tail := int64(500)
	if tailStr := strings.TrimSpace(r.URL.Query().Get("tail")); tailStr != "" {
		v, err := strconv.ParseInt(tailStr, 10, 64)
		if err != nil || v <= 0 {
			writeErr(w, http.StatusBadRequest, "tail must be a positive integer")
			return
		}
		if v > 5000 {
			v = 5000
		}
		tail = v
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	raw, err := s.manager.Logs(ctx, name, ns, tail)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			writeJSON(w, http.StatusOK, map[string]any{
				"name":      name,
				"namespace": ns,
				"tail":      tail,
				"logs":      "",
			})
			return
		}
		log.Printf("[honey-operator] LOGS ERROR ns=%s name=%s tail=%d err=%v", ns, name, tail, err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("[honey-operator] LOGS ns=%s name=%s tail=%d bytes=%d", ns, name, tail, len(raw))
	writeJSON(w, http.StatusOK, map[string]any{
		"name":      name,
		"namespace": ns,
		"tail":      tail,
		"logs":      string(raw),
	})
}

func ParseLogs(raw []byte) []HoneypotEvent {
	var events []HoneypotEvent
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev HoneypotEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}

		if ev.Action == "process" && ev.SrcIP == "0.0.0.0" {
			continue
		}
		ev.ID = eventKey(ev)
		events = append(events, ev)
	}
	return events
}

func eventKey(ev HoneypotEvent) string {
	raw := strings.Join([]string{
		ev.Timestamp, ev.Server, ev.SrcIP, ev.SrcPort,
		ev.DestIP, ev.DestPort, ev.Action, ev.Status,
		ev.Data, ev.Username, ev.Password,
	}, "\x1f")
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch := s.hub.Subscribe()
	defer s.hub.Unsubscribe(ch)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", ev)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, ErrorResponse{Error: msg})
}

func isUnavailableLogsErr(err error) bool {
	if err == nil {
		return false
	}
	if k8serrors.IsNotFound(err) || k8serrors.IsBadRequest(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "podinitializing") ||
		strings.Contains(msg, "containercreating") ||
		strings.Contains(msg, "is waiting to start") ||
		strings.Contains(msg, "container not found")
}
