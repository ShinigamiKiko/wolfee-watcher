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

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/wolfee-watcher/cert-server/internal/issuer"
	"github.com/wolfee-watcher/pkg/mtls"
)

const allowedNamespace = "wolfee-watcher"

const (
	maxIssueBodyBytes = 8 << 10
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 15 * time.Second
	idleTimeout       = 60 * time.Second
)

var serviceToAllowedSAs = map[mtls.ServiceType]map[string]struct{}{
	mtls.Sensor: {
		"sensor":                {},
		"wolfee-watcher-sensor": {},
	},
	mtls.TraceeBridge: {
		"tracee-bridge": {},
	},
	mtls.AnomalyDetector: {
		"anomaly-detector": {},
	},
	mtls.SentryAudit: {
		"sentry-audit": {},
	},
	mtls.ScannerAgent: {
		"scanner-agent": {},
	},
	mtls.AuditRunner: {
		"audit-runner": {},
	},
	mtls.HoneyOperator: {
		"honey-operator": {},
	},
	mtls.ForensicWatcher: {
		"forensic-watcher": {},
	},
	mtls.Kvisior: {
		"kvisior":     {},
		"kvisior8-ui": {},
	},
}

type issueRequest struct {
	Service string `json:"service"`
	Token   string `json:"token"`
}

type issueResponse struct {
	Cert      string `json:"cert"`
	Key       string `json:"key"`
	CA        string `json:"ca"`
	ExpiresAt string `json:"expires_at"`
}

type Server struct {
	addr string
	iss  *issuer.Issuer
	k8s  kubernetes.Interface
}

func New(addr string, iss *issuer.Issuer, k8s kubernetes.Interface) *Server {
	return &Server{addr: addr, iss: iss, k8s: k8s}
}

func (s *Server) Run() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok","service":"cert-server"}`)
	})

	mux.HandleFunc("/issue", s.handleIssue)

	log.Printf("[cert-server] listening on %s", s.addr)
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxIssueBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req issueRequest
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "invalid JSON: multiple JSON values are not allowed", http.StatusBadRequest)
		return
	}

	if req.Service == "" {
		http.Error(w, "service is required", http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	saName, err := s.validateToken(r.Context(), req.Token)
	if err != nil {
		log.Printf("[cert-server] token validation failed for %q: %v", req.Service, err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	svc := mtls.ServiceType(req.Service)
	if !isServiceAllowedForSA(svc, saName) {
		log.Printf("[cert-server] denied cert request: service=%q sa=%q", svc, saName)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	certPEM, keyPEM, err := s.iss.Issue(svc)
	if err != nil {
		log.Printf("[cert-server] issue cert for %q: %v", req.Service, err)
		http.Error(w, "cert issuance failed", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(issuer.CertLifetime)
	log.Printf("[cert-server] issued cert for %q, expires %s", req.Service, expiresAt.Format(time.RFC3339))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(issueResponse{
		Cert:      string(certPEM),
		Key:       string(keyPEM),
		CA:        string(s.iss.CAPEM()),
		ExpiresAt: expiresAt.Format(time.RFC3339),
	})
}

func (s *Server) validateToken(ctx context.Context, token string) (string, error) {
	review, err := s.k8s.AuthenticationV1().TokenReviews().Create(ctx,
		&authv1.TokenReview{
			Spec: authv1.TokenReviewSpec{Token: token},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("TokenReview API call: %w", err)
	}
	if !review.Status.Authenticated {
		return "", fmt.Errorf("token not authenticated")
	}

	ns := review.Status.User.Extra["authentication.kubernetes.io/namespace"]
	if len(ns) > 0 && ns[0] == allowedNamespace {
		sa := review.Status.User.Extra["authentication.kubernetes.io/serviceaccount.name"]
		if len(sa) > 0 && sa[0] != "" {
			return sa[0], nil
		}
	}

	username := review.Status.User.Username
	prefix := "system:serviceaccount:" + allowedNamespace + ":"
	if strings.HasPrefix(username, prefix) {
		saName := strings.TrimPrefix(username, prefix)
		if saName != "" {
			return saName, nil
		}
	}

	return "", fmt.Errorf("SA not in namespace %q (got %q)", allowedNamespace, username)
}

func isServiceAllowedForSA(svc mtls.ServiceType, saName string) bool {
	allowed, ok := serviceToAllowedSAs[svc]
	if !ok {
		return false
	}
	_, ok = allowed[saName]
	return ok
}
