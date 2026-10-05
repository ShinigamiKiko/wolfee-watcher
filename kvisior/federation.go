package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/auth"
	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

const (
	federationTokenHeader = "X-Federation-Token"
	federatedUserHeader   = "X-Federated-User"
	federatedRoleHeader   = "X-Federated-Role"
	endpointCacheTTL      = 30 * time.Second
)

type cachedEndpoint struct {
	url     string
	enabled bool
	expires time.Time
}

type federation struct {
	st        *store.Store
	token     string
	advertise string
	transport http.RoundTripper

	mu    sync.Mutex
	cache map[string]cachedEndpoint
}

func newFederation(st *store.Store) *federation {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile := strings.TrimSpace(os.Getenv("KVISIOR_FEDERATION_CA_FILE")); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatalf("[federation] read KVISIOR_FEDERATION_CA_FILE: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatalf("[federation] no certificates in %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	f := &federation{
		st:        st,
		token:     strings.TrimSpace(os.Getenv("KVISIOR_FEDERATION_TOKEN")),
		advertise: strings.TrimRight(strings.TrimSpace(os.Getenv("KVISIOR_ADVERTISE_URL")), "/"),
		transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     tlsCfg,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
		},
		cache: make(map[string]cachedEndpoint),
	}
	log.Printf("[federation] token configured=%v, advertised endpoint=%q", f.token != "", f.advertise)
	return f
}

func (f *federation) register(ctx context.Context) {
	if f.st == nil || f.advertise == "" {
		return
	}
	go func() {
		for delay := time.Second; ; delay = min(2*delay, time.Minute) {
			regCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := f.st.SetClusterEndpoint(regCtx, clusterctx.Local(), f.advertise)
			cancel()
			if err == nil {
				log.Printf("[federation] advertised %q as the endpoint of cluster %q", f.advertise, clusterctx.Local())
				return
			}
			log.Printf("[federation] advertise %q for %q: %v (retrying in %s)", f.advertise, clusterctx.Local(), err, delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()
}

func (f *federation) trusted(r *http.Request) bool {
	if f.token == "" {
		return false
	}
	got := r.Header.Get(federationTokenHeader)
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(f.token)) == 1
}

func (f *federation) requireAuth(authMgr *auth.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		guarded := authMgr.RequireAuth(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if f.trusted(r) {
				user := r.Header.Get(federatedUserHeader)
				role := r.Header.Get(federatedRoleHeader)
				if user == "" || (role != "admin" && role != "ro") {
					writeFederationError(w, http.StatusUnauthorized, "federated request without an acting user", "")
					return
				}
				r.Header.Set("X-Acting-User", user)
				r.Header.Set("X-Acting-Role", role)
				next.ServeHTTP(w, r)
				return
			}
			token, fedUser, fedRole := r.Header.Get(federationTokenHeader), r.Header.Get(federatedUserHeader), r.Header.Get(federatedRoleHeader)
			if token != "" || fedUser != "" || fedRole != "" {
				slog.Warn("federation_headers_rejected",
					"component", "kvisior/federation",
					"method", r.Method,
					"path", r.URL.Path,
					"remote", r.RemoteAddr,
					"token_present", token != "",
					"claimed_user", auth.ClipForLog(fedUser),
					"claimed_role", auth.ClipForLog(fedRole))
			}
			r.Header.Del(federationTokenHeader)
			r.Header.Del(federatedUserHeader)
			r.Header.Del(federatedRoleHeader)
			guarded.ServeHTTP(w, r)
		})
	}
}

func (f *federation) endpoint(ctx context.Context, cluster string) (cachedEndpoint, error) {
	f.mu.Lock()
	if e, ok := f.cache[cluster]; ok && time.Now().Before(e.expires) {
		f.mu.Unlock()
		return e, nil
	}
	f.mu.Unlock()

	ep, enabled, err := f.st.ClusterEndpoint(ctx, cluster)
	if err != nil {
		return cachedEndpoint{}, err
	}
	e := cachedEndpoint{url: ep, enabled: enabled, expires: time.Now().Add(endpointCacheTTL)}
	f.mu.Lock()
	f.cache[cluster] = e
	f.mu.Unlock()
	return e, nil
}

func (f *federation) route(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cluster := clusterctx.ForRead(r)
		if clusterctx.Hub() && cluster == "" {
			writeFederationError(w, http.StatusBadRequest, "select a cluster first", "")
			return
		}
		if f == nil || f.st == nil || (!clusterctx.Hub() && cluster == clusterctx.Local()) || f.trusted(r) {
			next.ServeHTTP(w, r)
			return
		}
		if f.token == "" {
			writeFederationError(w, http.StatusBadGateway,
				"federation is not configured on this kvisior (KVISIOR_FEDERATION_TOKEN is empty)", cluster)
			return
		}
		ep, err := f.endpoint(r.Context(), cluster)
		if err != nil {
			writeFederationError(w, http.StatusBadGateway, "cluster registry lookup failed", cluster)
			return
		}
		if ep.url == "" {
			writeFederationError(w, http.StatusBadGateway,
				"cluster has no registered kvisior endpoint; live data is unavailable", cluster)
			return
		}
		if !ep.enabled {
			writeFederationError(w, http.StatusBadGateway, "cluster is disabled", cluster)
			return
		}
		target, err := url.Parse(ep.url)
		if err != nil || target.Host == "" {
			writeFederationError(w, http.StatusBadGateway, "cluster endpoint is not a valid URL", cluster)
			return
		}

		user := r.Header.Get("X-Acting-User")
		role := r.Header.Get("X-Acting-Role")
		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.URL.Path = strings.TrimRight(target.Path, "/") + pr.In.URL.Path
				pr.Out.URL.RawPath = ""
				pr.Out.Host = target.Host
				pr.Out.Header.Del("Cookie")
				pr.Out.Header.Del("Authorization")
				pr.Out.Header.Set(federationTokenHeader, f.token)
				pr.Out.Header.Set(federatedUserHeader, user)
				pr.Out.Header.Set(federatedRoleHeader, role)
				pr.Out.Header.Set(clusterctx.Header, cluster)
				q := pr.Out.URL.Query()
				if q.Has(clusterctx.QueryParam) {
					q.Set(clusterctx.QueryParam, cluster)
					pr.Out.URL.RawQuery = q.Encode()
				}
			},
			Transport:     f.transport,
			FlushInterval: -1,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				if r.Context().Err() != nil {
					return
				}
				log.Printf("[federation] %s %s -> cluster %q (%s): %v", r.Method, r.URL.Path, cluster, target.Host, err)
				writeFederationError(w, http.StatusBadGateway, "cluster kvisior is unreachable", cluster)
			},
		}
		proxy.ServeHTTP(w, r)
	})
}

func writeFederationError(w http.ResponseWriter, code int, msg, cluster string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Federation-Error", "1")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg, "cluster": cluster})
}

func (f *federation) routeFunc(h func(http.ResponseWriter, *http.Request)) http.Handler {
	return f.route(http.HandlerFunc(h))
}
