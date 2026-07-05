package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/wolfee-watcher/pkg/httputil"
)

const maxBaselineBodyBytes = 4 * 1024

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func validDigest(d string) bool { return digestRE.MatchString(d) }

type DigestStore interface {
	Get(name, tag string) (*DigestBaseline, bool)
	Set(name, tag, digest string) DigestBaseline
	Delete(name, tag string)
	List() []DigestBaseline
}

type DigestBaseline struct {
	ImageName  string    `json:"imageName"`
	ImageTag   string    `json:"imageTag"`
	Digest     string    `json:"digest"`
	RecordedAt time.Time `json:"recordedAt"`
}

type DigestStatus struct {
	ImageName  string    `json:"imageName"`
	ImageTag   string    `json:"imageTag"`
	Baseline   string    `json:"baseline"`
	Current    string    `json:"current"`
	Changed    bool      `json:"changed"`
	RecordedAt time.Time `json:"recordedAt"`
}

type baselineKey struct{ name, tag string }

type memoryDigestStore struct {
	mu   sync.RWMutex
	data map[baselineKey]DigestBaseline

	push func([]DigestBaseline)
}

func newDigestStore(kv *kvClient) DigestStore {
	m := &memoryDigestStore{data: make(map[baselineKey]DigestBaseline)}
	if kv.enabled() {
		m.push = func(list []DigestBaseline) { kv.PushScannerState("baselines", list) }
		var list []DigestBaseline
		if kv.PullScannerState("baselines", &list) {
			for _, b := range list {
				m.data[baselineKey{b.ImageName, b.ImageTag}] = b
			}
			log.Printf("[state] restored %d baselines from kvisior", len(list))
		}
	}
	return m
}

func (m *memoryDigestStore) persist() {
	if m.push == nil {
		return
	}
	m.mu.RLock()
	list := make([]DigestBaseline, 0, len(m.data))
	for _, b := range m.data {
		list = append(list, b)
	}
	m.mu.RUnlock()
	m.push(list)
}

func (m *memoryDigestStore) Get(name, tag string) (*DigestBaseline, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.data[baselineKey{name, tag}]
	if !ok {
		return nil, false
	}
	return &b, true
}

func (m *memoryDigestStore) Set(name, tag, digest string) DigestBaseline {
	b := DigestBaseline{
		ImageName:  name,
		ImageTag:   tag,
		Digest:     digest,
		RecordedAt: time.Now().UTC(),
	}
	m.mu.Lock()
	m.data[baselineKey{name, tag}] = b
	m.mu.Unlock()
	m.persist()
	return b
}

func (m *memoryDigestStore) Delete(name, tag string) {
	m.mu.Lock()
	delete(m.data, baselineKey{name, tag})
	m.mu.Unlock()
	m.persist()
}

func (m *memoryDigestStore) List() []DigestBaseline {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DigestBaseline, 0, len(m.data))
	for _, b := range m.data {
		out = append(out, b)
	}
	return out
}

func (s *Server) registerBaselineRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/baselines", httputil.CORS(s.handleBaselines))
	mux.HandleFunc("/baselines/status", httputil.CORS(s.handleBaselineStatus))
}

func (s *Server) handleBaselines(w http.ResponseWriter, r *http.Request) {
	switch r.Method {

	case http.MethodGet:
		list := s.baselines.List()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxBaselineBodyBytes)
		var req struct {
			ImageName string `json:"imageName"`
			ImageTag  string `json:"imageTag"`
			Digest    string `json:"digest"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			if err == io.ErrUnexpectedEOF || err.Error() == "http: request body too large" {
				http.Error(w, `{"error":"request too large"}`, http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			}
			return
		}
		if req.ImageName == "" || req.Digest == "" {
			http.Error(w, `{"error":"imageName and digest required"}`, http.StatusBadRequest)
			return
		}
		if !validDigest(req.Digest) {
			http.Error(w, `{"error":"digest must be sha256:<64 hex chars>"}`, http.StatusBadRequest)
			return
		}
		if req.ImageTag == "" {
			req.ImageTag = "latest"
		}
		b := s.baselines.Set(req.ImageName, req.ImageTag, req.Digest)
		log.Printf("[baselines] set %s:%s → %s…", req.ImageName, req.ImageTag, req.Digest[:16])
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(b)

	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		tag := r.URL.Query().Get("tag")
		if name == "" {
			http.Error(w, `{"error":"name required"}`, http.StatusBadRequest)
			return
		}
		if tag == "" {
			tag = "latest"
		}
		s.baselines.Delete(name, tag)
		log.Printf("[baselines] deleted %s:%s", name, tag)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBaselineStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	tag := r.URL.Query().Get("tag")
	current := r.URL.Query().Get("current")

	if name == "" || current == "" {
		http.Error(w, `{"error":"name and current required"}`, http.StatusBadRequest)
		return
	}
	if !validDigest(current) {
		http.Error(w, `{"error":"current must be sha256:<64 hex chars>"}`, http.StatusBadRequest)
		return
	}
	if tag == "" {
		tag = "latest"
	}

	baseline, exists := s.baselines.Get(name, tag)
	if !exists {
		b := s.baselines.Set(name, tag, current)
		baseline = &b
		log.Printf("[baselines] auto-baseline %s:%s → %s…", name, tag, current[:16])
	}

	status := DigestStatus{
		ImageName:  name,
		ImageTag:   tag,
		Baseline:   baseline.Digest,
		Current:    current,
		Changed:    baseline.Digest != current,
		RecordedAt: baseline.RecordedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
