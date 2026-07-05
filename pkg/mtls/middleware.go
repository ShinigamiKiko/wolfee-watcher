package mtls

import (
	"net/http"
	"path"
	"slices"
)

func RequireService(allowed ...ServiceType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller, ok := ServiceTypeFromRequest(r)
			if !ok {
				http.Error(w, "mTLS: no client certificate", http.StatusUnauthorized)
				return
			}
			if !slices.Contains(allowed, caller) {
				http.Error(w, "mTLS: caller "+string(caller)+" not authorised", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireAnyService(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ServiceTypeFromRequest(r); !ok {
			http.Error(w, "mTLS: no client certificate", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func SecureMuxExcept(next http.Handler, exempt ...string) http.Handler {
	ex := make(map[string]struct{}, len(exempt))
	for _, p := range exempt {
		ex[p] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cleaned := path.Clean(r.URL.Path)
		if _, skip := ex[cleaned]; skip {
			next.ServeHTTP(w, r)
			return
		}
		RequireAnyService(next).ServeHTTP(w, r)
	})
}

func RequireServiceExcept(next http.Handler, allowed []ServiceType, exempt ...string) http.Handler {
	ex := make(map[string]struct{}, len(exempt))
	for _, p := range exempt {
		ex[p] = struct{}{}
	}
	guard := RequireService(allowed...)(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, skip := ex[path.Clean(r.URL.Path)]; skip {
			next.ServeHTTP(w, r)
			return
		}
		guard.ServeHTTP(w, r)
	})
}
