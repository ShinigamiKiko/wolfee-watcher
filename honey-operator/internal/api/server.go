package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/wolfee-watcher/honey-operator/internal/decoy"
	"github.com/wolfee-watcher/honey-operator/internal/k8s"
	"github.com/wolfee-watcher/honey-operator/internal/registry"
	"github.com/wolfee-watcher/pkg/httputil"
	"github.com/wolfee-watcher/pkg/mtls"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

var honeypotNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type Server struct {
	addr    string
	ctx     context.Context
	manager *k8s.Manager
	hub     Hub
	reg     *registry.Client
}

func New(ctx context.Context, addr string, manager *k8s.Manager, hub Hub, reg *registry.Client) *Server {
	return &Server{addr: addr, ctx: ctx, manager: manager, hub: hub, reg: reg}
}

func (s *Server) records(ctx context.Context) []registry.Record {
	if s.reg.Enabled() {
		if recs, err := s.reg.List(ctx); err == nil {
			s.hub.SetRecords(recs)
			return recs
		}
	}
	return s.hub.Records()
}

func (s *Server) findRecord(ctx context.Context, ns, name string) (registry.Record, bool) {
	for _, rec := range s.records(ctx) {
		if rec.Namespace == ns && rec.Name == name {
			return rec, true
		}
	}
	return registry.Record{}, false
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
	ctx := r.Context()

	result := make([]HoneypotStatus, 0)
	for _, rec := range s.records(ctx) {
		if ns != "" && rec.Namespace != ns {
			continue
		}
		st := s.manager.InspectDecoy(ctx, rec)
		pods := make([]string, 0, len(st.Pods))
		for _, p := range st.Pods {
			pods = append(pods, p.Name)
		}
		result = append(result, HoneypotStatus{
			ID:        rec.ID,
			Name:      rec.Name,
			Namespace: rec.Namespace,
			Kind:      rec.Kind,
			Service:   rec.Service,
			Services:  []string{rec.Service},
			Port:      rec.Port,
			ClusterIP: st.ClusterIP,
			Phase:     st.Phase,
			State:     st.State,
			Image:     rec.Image,
			Pods:      pods,
			CreatedBy: rec.CreatedBy,
			CreatedAt: rec.CreatedAt,
		})
	}

	legacy, err := s.manager.List(ctx, ns)
	if err != nil {
		log.Printf("[honey-operator] legacy list ns=%s err=%v", ns, err)
	}
	for _, pod := range legacy {
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
		ip := ""
		if svc, err := s.manager.GetService(ctx, name, pod.Namespace); err == nil {
			ip = svc.Spec.ClusterIP
		}
		result = append(result, HoneypotStatus{
			Name:      name,
			Namespace: pod.Namespace,
			Kind:      "Pod",
			Services:  services,
			ClusterIP: ip,
			Phase:     string(pod.Status.Phase),
			State:     k8s.StateReady,
			Pods:      []string{pod.Name},
			Legacy:    true,
			CreatedAt: pod.CreationTimestamp.Time,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"honeypots": result,
		"total":     len(result),
		"catalog":   catalogView(),
	})
}

func catalogView() []map[string]any {
	out := []map[string]any{}
	for _, p := range decoy.All() {
		out = append(out, map[string]any{
			"service": p.Service, "kind": p.Kind, "defaultName": p.DefaultName,
			"port": p.Port, "image": p.Image(), "app": p.AppName,
		})
	}
	return out
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var spec HoneypotSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	service := strings.TrimSpace(spec.Service)
	if service == "" && len(spec.Services) == 1 {
		service = spec.Services[0]
	}
	if service == "" {
		writeErr(w, http.StatusBadRequest, "choose exactly one service")
		return
	}
	profile, ok := decoy.Lookup(service)
	if !ok {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("unsupported service %q", service))
		return
	}
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = profile.DefaultName
	}
	if !honeypotNameRe.MatchString(name) || len(name) > 40 {
		writeErr(w, http.StatusBadRequest, `name must be a DNS-1123 label: lowercase letters, digits and "-" (max 40 chars)`)
		return
	}
	if spec.Namespace == "" {
		spec.Namespace = mtls.Namespace()
	}
	if !s.reg.Enabled() {
		writeErr(w, http.StatusServiceUnavailable, "honeypot registry is not configured (KVISIOR_PUSH_URL)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	if err := s.manager.CheckNamespace(ctx, spec.Namespace); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("namespace %q not found", spec.Namespace))
		return
	}

	rec, err := s.manager.CreateDecoy(ctx, spec.Namespace, name, profile)
	if errors.Is(err, k8s.ErrNameTaken) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("%q is already used in namespace %s: pick another name", name, spec.Namespace))
		return
	}
	if err != nil {
		log.Printf("[honey-operator] CREATE ERROR name=%s ns=%s service=%s err=%v", name, spec.Namespace, service, err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rec.CreatedBy = strings.TrimSpace(r.Header.Get("X-Acting-User"))
	if err := s.reg.Register(ctx, rec); err != nil {
		s.manager.RollbackDecoy(context.Background(), rec)
		log.Printf("[honey-operator] REGISTER ERROR name=%s ns=%s err=%v", name, spec.Namespace, err)
		writeErr(w, http.StatusBadGateway, "objects were rolled back: "+err.Error())
		return
	}
	go s.hub.Refresh(s.ctx)

	log.Printf("[honey-operator] created honeypot %s/%s kind=%s service=%s id=%s", spec.Namespace, name, rec.Kind, service, rec.ID)
	writeJSON(w, http.StatusCreated, rec)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, name string) {
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = mtls.Namespace()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	if rec, ok := s.findRecord(ctx, ns, name); ok {
		if err := s.manager.DeleteDecoy(ctx, rec); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.reg.Unregister(ctx, rec.ID); err != nil {
			writeErr(w, http.StatusBadGateway, "objects deleted, registry not updated: "+err.Error())
			return
		}
		go s.hub.Refresh(s.ctx)
		log.Printf("[honey-operator] deleted honeypot %s/%s id=%s", ns, name, rec.ID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		return
	}

	if err := s.manager.Delete(ctx, name, ns); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("[honey-operator] deleted legacy honeypot %s/%s", ns, name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) recordLogs(ctx context.Context, ns, name string, tail int64) ([]byte, error) {
	rec, ok := s.findRecord(ctx, ns, name)
	if !ok {
		return s.manager.Logs(ctx, name, ns, tail)
	}
	var out []byte
	for _, pod := range s.manager.OwnedPods(ctx, rec) {
		raw, err := s.manager.PodLogs(ctx, ns, pod.Name, tail)
		if err != nil {
			continue
		}
		out = append(out, raw...)
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			out = append(out, '\n')
		}
	}
	return out, nil
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, name string) {
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = mtls.Namespace()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	raw, err := s.recordLogs(ctx, ns, name, 500)
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
		ns = mtls.Namespace()
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

	raw, err := s.recordLogs(ctx, ns, name, tail)
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
	sum := sha256.Sum256([]byte(raw))
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

	if _, err := io.WriteString(w, ": connected\n\n"); err != nil {
		return
	}
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if _, err := io.WriteString(w, "data: "+string(ev)+"\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, err := io.WriteString(w, ": heartbeat\n\n"); err != nil {
				return
			}
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
