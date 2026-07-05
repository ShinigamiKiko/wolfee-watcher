package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *Server) handleNodeRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/nodes/"), "/")
	if len(parts) != 2 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"error": "use /api/nodes/{name}/events"})
		return
	}
	nodeName, action := parts[0], parts[1]
	switch action {
	case "events":
		s.handleNodeEvents(w, r, nodeName)
	default:
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"error": "unknown action: " + action})
	}
}

func (s *Server) handleNodeEvents(w http.ResponseWriter, r *http.Request, nodeName string) {
	sel := "involvedObject.name=" + nodeName + ",involvedObject.kind=Node"
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	evList, err := s.client.CoreV1().Events("").List(ctx, metav1.ListOptions{FieldSelector: sel})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	type evRow struct {
		Time    string `json:"time"`
		Type    string `json:"type"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
		Count   int32  `json:"count"`
		Source  string `json:"source"`
	}
	rows := make([]evRow, 0, len(evList.Items))
	for _, e := range evList.Items {
		rows = append(rows, evRow{Time: eventTimestamp(e), Type: e.Type, Reason: e.Reason, Message: e.Message, Count: e.Count, Source: e.Source.Component})
	}
	json.NewEncoder(w).Encode(map[string]any{"node": nodeName, "events": rows, "fetchedAt": time.Now().UTC().Format(time.RFC3339Nano)})
}

func eventTimestamp(e corev1.Event) string {
	if !e.LastTimestamp.IsZero() {
		return e.LastTimestamp.UTC().Format(time.RFC3339)
	}
	if !e.EventTime.IsZero() {
		return e.EventTime.UTC().Format(time.RFC3339)
	}
	return ""
}

func (s *Server) handleForensicWatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	log.Printf("[sensor] handleForensicWatch path=%q method=%s", r.URL.Path, r.Method)
	ns, pod, ok := parseForensicTarget(strings.TrimPrefix(r.URL.Path, "/sensor"), "/api/forensic/watch/")
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"error": "use /api/forensic/watch/{ns}/{pod}"})
		return
	}
	if r.Method == http.MethodDelete {
		s.proxyToForensicWatcher(w, r, ns, pod, "unwatch/"+ns+"/"+pod, http.MethodDelete)
		return
	}
	s.proxyToForensicWatcher(w, r, ns, pod, "watch/"+ns+"/"+pod, http.MethodPost)
}

func (s *Server) handleForensicDiff(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ns, pod, ok := parseForensicTarget(strings.TrimPrefix(r.URL.Path, "/sensor"), "/api/forensic/diff/")
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"error": "use /api/forensic/diff/{ns}/{pod}"})
		return
	}
	s.proxyToForensicWatcher(w, r, ns, pod, "diff/"+ns+"/"+pod, http.MethodGet)
}

func (s *Server) handleForensicTar(w http.ResponseWriter, r *http.Request) {
	log.Printf("[sensor] handleForensicTar path=%q", r.URL.Path)
	ns, pod, ok := parseForensicTarget(strings.TrimPrefix(r.URL.Path, "/sensor"), "/api/forensic/tar/")
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.proxyToForensicWatcher(w, r, ns, pod, "tar/"+ns+"/"+pod, http.MethodGet)
}

func parseForensicTarget(path, prefix string) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	log.Printf("[sensor] forensic path=%q parts=%v len=%d", path, parts, len(parts))
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (s *Server) proxyToForensicWatcher(w http.ResponseWriter, r *http.Request, ns, pod, path, method string) {
	s.mu.RLock()
	nodeName, ok := s.podNode[ns+"/"+pod]
	podCount := s.podCount
	s.mu.RUnlock()
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"error": "snapshot not ready"})
		return
	}
	if nodeName == "" {
		log.Printf("[sensor] pod not found: ns=%s pod=%s (snapshot has %d pods)", ns, pod, podCount)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"error": "pod not found in snapshot"})
		return
	}
	watcherIP, err := s.findForensicWatcherIP(r.Context(), nodeName)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"error": fmt.Sprintf("forensic-watcher not found on node %s: %v", nodeName, err)})
		return
	}
	targetURL := fmt.Sprintf("https://%s:9090/%s", watcherIP, path)
	log.Printf("[sensor] forensic proxy → %s", targetURL)
	proxyReq, err := http.NewRequestWithContext(r.Context(), method, targetURL, r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp, err := s.httpClient.Do(proxyReq)
	if err != nil {
		log.Printf("[sensor] forensic proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("[sensor] forensic proxy stream broken: %v", err)
	}
}

func copyResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
}

func (s *Server) findForensicWatcherIP(ctx context.Context, nodeName string) (string, error) {
	pods, err := s.client.CoreV1().Pods("wolfee-watcher").List(ctx, metav1.ListOptions{
		LabelSelector: "app=forensic-watcher",
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return "", err
	}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" {
			return p.Status.PodIP, nil
		}
	}
	return "", fmt.Errorf("no running forensic-watcher on node %s", nodeName)
}
