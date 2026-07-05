package server

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/wolfee-watcher/pkg/mtls"
)

func Run(ctx context.Context, tlsCfg *tls.Config, webhookMux, apiMux http.Handler) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   webhookMux,
		TLSConfig: tlsCfg,
		ErrorLog:  newFilteredLogger("[sentry-audit/webhook]"),
	}

	go func() {
		log.Printf("[sentry-audit] webhook TLS listener on :8443")
		err := srv.ListenAndServeTLS("", "")
		if err == http.ErrServerClosed {
			err = nil
		}
		errCh <- err
	}()

	go func() {
		log.Printf("[sentry-audit] API mTLS listener on :8080")
		errCh <- mtls.ListenAuto(runCtx, ":8080", mtls.SecureMuxExcept(logRequests(apiMux), "/health"), mtls.SentryAudit, true)
	}()

	first := <-errCh
	if first != nil {
		log.Printf("[sentry-audit] listener exited with error: %v — shutting down peer listener", first)
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)

	second := <-errCh
	if first == nil {
		return second
	}
	if second != nil {
		log.Printf("[sentry-audit] peer listener also exited with error: %v", second)
	}
	return first
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		log.Printf("[sentry-audit] %s %s → %d (%s) from %s",
			r.Method, r.URL.Path, rw.status,
			time.Since(start).Round(time.Millisecond),
			r.RemoteAddr)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func newFilteredLogger(prefix string) *log.Logger {
	return log.New(logWriter{prefix: prefix}, "", 0)
}

type logWriter struct{ prefix string }

func (lw logWriter) Write(p []byte) (int, error) {
	msg := string(p)
	if strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset") {
		return len(p), nil
	}
	log.Printf("%s %s", lw.prefix, strings.TrimSpace(msg))
	return len(p), nil
}
