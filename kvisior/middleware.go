package main

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

func mutationsRequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/auth/change-password") {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-Acting-Role") != "admin" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"admin role required"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func internalAuthOK(secret string, r *http.Request) bool {
	if secret == "" {

		return false
	}
	got := []byte(r.Header.Get("X-Internal-Push-Secret"))
	return subtle.ConstantTimeCompare(got, []byte(secret)) == 1
}

func pushSecretMiddleware(secret string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !internalAuthOK(secret, r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}
}

func internalPushAuth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !internalAuthOK(secret, r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
