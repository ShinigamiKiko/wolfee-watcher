package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/auth"
)

func registerBackendProxies(mux *http.ServeMux, scheme string, baseTransport http.RoundTripper, authMgr *auth.Manager) {
	for _, b := range backends {
		target, err := url.Parse(scheme + "://" + b.host)
		if err != nil {
			log.Fatalf("[kvisior] invalid backend %q: %v", b.host, err)
		}

		c := &http.Client{
			Transport: baseTransport,
			Timeout:   b.timeout,
		}

		prefix := b.prefix
		flushInterval := -1 * time.Second
		if prefix == "/api/" || prefix == "/anomaly/" {

			flushInterval = 200 * time.Millisecond
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(req *httputil.ProxyRequest) {
				req.SetURL(target)
				stripped := strings.TrimPrefix(req.In.URL.Path, strings.TrimSuffix(prefix, "/"))
				if stripped == "" {
					stripped = "/"
				}
				req.Out.URL.Path = stripped
				req.Out.URL.RawPath = ""
				req.Out.Host = target.Host
			},
			Transport:     c.Transport,
			FlushInterval: flushInterval,
			ModifyResponse: func(resp *http.Response) error {

				isSSE := false
				if resp.Request != nil {
					p := resp.Request.URL.Path
					if prefix == "/anomaly/" && p == "/api/events/stream" {
						isSSE = true
					}
					if prefix == "/scanner/" && p == "/stream" {
						isSSE = true
					}
				}
				if isSSE {
					resp.Header.Set("Cache-Control", "no-cache, no-transform")
					resp.Header.Set("X-Accel-Buffering", "no")
					resp.Header.Del("Content-Length")
				}
				return nil
			},

			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				if err.Error() == "context canceled" {
					return
				}
				log.Printf("[kvisior] proxy error %s %s: %v", r.Method, r.URL.Path, err)
				w.WriteHeader(http.StatusBadGateway)
			},
		}

		mux.Handle(prefix, authMgr.RequireAuth(mutationsRequireAdmin(proxy)))
		log.Printf("[kvisior] proxy %s → %s://%s (timeout=%v)", prefix, scheme, b.host, b.timeout)
	}
}
