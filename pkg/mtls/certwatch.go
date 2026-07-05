package mtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

const (
	certLifetime3h = 3 * time.Hour
	renewBefore1h  = 1 * time.Hour
)

var certHTTPClient = &http.Client{Timeout: 30 * time.Second}

func certServerAddr() string {
	if v := os.Getenv("CERT_SERVER_ADDR"); v != "" {
		return v
	}
	return "http://cert-server.wolfee-watcher.svc.cluster.local:8090"
}

func saToken() (string, error) {
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", fmt.Errorf("certwatch: read SA token: %w", err)
	}
	return string(bytes.TrimSpace(b)), nil
}

type issuedCert struct {
	Cert      string `json:"cert"`
	Key       string `json:"key"`
	CA        string `json:"ca"`
	ExpiresAt string `json:"expires_at"`
}

func fetchCert(ctx context.Context, svc ServiceType) (*issuedCert, error) {
	token, err := saToken()
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(map[string]string{
		"service": string(svc),
		"token":   token,
	})
	if err != nil {
		return nil, fmt.Errorf("certwatch: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, certServerAddr()+"/issue", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("certwatch: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := certHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certwatch: POST /issue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certwatch: cert-server returned %d", resp.StatusCode)
	}

	var ic issuedCert
	if err := json.NewDecoder(resp.Body).Decode(&ic); err != nil {
		return nil, fmt.Errorf("certwatch: decode response: %w", err)
	}
	return &ic, nil
}

type CertHolder struct {
	svc  ServiceType
	cert atomic.Pointer[tls.Certificate]
	ca   atomic.Pointer[[]byte]
}

func NewCertHolder(ctx context.Context, svc ServiceType) (*CertHolder, error) {
	h := &CertHolder{svc: svc}

	var ic *issuedCert
	var err error
	for attempt := 1; attempt <= 15; attempt++ {
		ic, err = fetchCert(ctx, svc)
		if err == nil {
			break
		}
		log.Printf("[certwatch] cert-server not ready (attempt %d/15): %v — retrying in 5s", attempt, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	if err != nil {
		return nil, fmt.Errorf("certwatch: initial cert fetch: %w", err)
	}
	if err := h.store(ic); err != nil {
		return nil, err
	}
	log.Printf("[certwatch] cert issued for %q, expires %s", svc, ic.ExpiresAt)

	go h.renewLoop(ctx, ic.ExpiresAt)
	return h, nil
}

func (h *CertHolder) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := h.cert.Load()
	if c == nil {
		return nil, fmt.Errorf("certwatch: no certificate loaded")
	}
	return c, nil
}

func (h *CertHolder) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return h.GetCertificate(nil)
}

func (h *CertHolder) CA() []byte {
	if p := h.ca.Load(); p != nil {
		return *p
	}
	return nil
}

func (h *CertHolder) store(ic *issuedCert) error {
	tlsCert, err := tls.X509KeyPair([]byte(ic.Cert), []byte(ic.Key))
	if err != nil {
		return fmt.Errorf("certwatch: parse cert/key pair: %w", err)
	}
	h.cert.Store(&tlsCert)
	ca := []byte(ic.CA)
	h.ca.Store(&ca)
	return nil
}

func (h *CertHolder) renewLoop(ctx context.Context, firstExpiry string) {
	expiryStr := firstExpiry
	for {
		expiry, err := time.Parse(time.RFC3339, expiryStr)
		if err != nil {
			log.Printf("[certwatch] bad expiry %q: %v — retrying in 10m", expiryStr, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Minute):
				expiry = time.Now().Add(renewBefore1h)
			}
		}

		sleepUntil := expiry.Add(-renewBefore1h)
		waitDur := time.Until(sleepUntil)
		if waitDur < 0 {
			waitDur = 0
		}

		log.Printf("[certwatch] next renewal for %q in %s", h.svc, waitDur.Round(time.Second))

		select {
		case <-ctx.Done():
			log.Printf("[certwatch] stopping renewal for %q", h.svc)
			return
		case <-time.After(waitDur):
		}

		for attempt := 1; ; attempt++ {
			ic, err := fetchCert(ctx, h.svc)
			if err != nil {
				backoff := time.Duration(attempt*attempt) * 10 * time.Second
				if backoff > 5*time.Minute {
					backoff = 5 * time.Minute
				}
				log.Printf("[certwatch] renew failed (attempt %d): %v — retry in %s", attempt, err, backoff)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
					continue
				}
			}
			if err := h.store(ic); err != nil {
				log.Printf("[certwatch] store renewed cert: %v", err)
			} else {
				log.Printf("[certwatch] cert renewed for %q, expires %s", h.svc, ic.ExpiresAt)
				expiryStr = ic.ExpiresAt
			}
			break
		}
	}
}

func ListenAuto(ctx context.Context, addr string, handler http.Handler, svc ServiceType, permissive bool) error {
	if os.Getenv("CERT_SERVER_ADDR") == "" {

		if v := os.Getenv("MTLS_REQUIRED"); (v == "1" || v == "true" || v == "TRUE") && os.Getenv("MTLS_CA_FILE") == "" {
			return fmt.Errorf("mtls: MTLS_REQUIRED set but no CERT_SERVER_ADDR/MTLS_CA_FILE configured — refusing to serve plaintext")
		}
		if permissive {
			return ListenPermissive(ctx, addr, handler)
		}
		return Listen(ctx, addr, handler)
	}

	h, err := NewCertHolder(ctx, svc)
	if err != nil {
		return fmt.Errorf("certwatch: %w", err)
	}
	return ListenWithHolder(ctx, addr, handler, h, permissive)
}
