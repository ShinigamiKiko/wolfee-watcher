package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"time"
)

const (
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 15 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 60 * time.Second
)

func newHTTPServer(addr string, handler http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
	}
}

func serveGraceful(ctx context.Context, srv *http.Server, useTLS bool) error {
	serveErr := make(chan error, 1)
	go func() {
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if err == http.ErrServerClosed {
			err = nil
		}
		serveErr <- err
	}()
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}

func Listen(ctx context.Context, addr string, handler http.Handler) error {
	certs, err := TryLoad()
	if err != nil {
		return fmt.Errorf("mtls: load certs: %w", err)
	}
	if certs == nil {
		return fmt.Errorf("mtls: no certificates configured (set MTLS_CA_FILE or CERT_SERVER_ADDR) — refusing to start plaintext HTTP listener on %s", addr)
	}
	tlsCfg, err := ServerConfig(certs)
	if err != nil {
		return fmt.Errorf("mtls: build server config: %w", err)
	}
	log.Printf("[mtls] mTLS HTTPS on %s (TLS 1.3, RequireAndVerifyClientCert)", addr)
	return serveGraceful(ctx, newHTTPServer(addr, handler, tlsCfg), true)
}

func ListenPermissive(ctx context.Context, addr string, handler http.Handler) error {
	certs, err := TryLoad()
	if err != nil {
		return fmt.Errorf("mtls: load certs: %w", err)
	}
	if certs == nil {
		return fmt.Errorf("mtls: no certificates configured (set MTLS_CA_FILE or CERT_SERVER_ADDR) — refusing to start plaintext HTTP listener on %s", addr)
	}
	tlsCfg, err := ServerConfig(certs)
	if err != nil {
		return fmt.Errorf("mtls: build server config: %w", err)
	}
	tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	log.Printf("[mtls] permissive mTLS HTTPS on %s (VerifyClientCertIfGiven)", addr)
	return serveGraceful(ctx, newHTTPServer(addr, handler, tlsCfg), true)
}

func ListenWithHolder(ctx context.Context, addr string, handler http.Handler, h *CertHolder, permissive bool) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(h.CA()) {
		return fmt.Errorf("mtls: failed to parse CA from cert holder")
	}

	clientAuth := tls.RequireAndVerifyClientCert
	label := "RequireAndVerifyClientCert"
	if permissive {
		clientAuth = tls.VerifyClientCertIfGiven
		label = "VerifyClientCertIfGiven"
	}

	tlsCfg := &tls.Config{
		GetCertificate: h.GetCertificate,
		ClientAuth:     clientAuth,
		ClientCAs:      pool,
		MinVersion:     tls.VersionTLS13,
	}

	log.Printf("[mtls] cert-rotation HTTPS on %s (TLS 1.3, %s)", addr, label)
	return serveGraceful(ctx, newHTTPServer(addr, handler, tlsCfg), true)
}
