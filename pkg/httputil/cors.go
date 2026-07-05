package httputil

import (
	"net/http"
	"os"
)

func CORS(next http.HandlerFunc) http.HandlerFunc {
	allowedOrigin := os.Getenv("CORS_ALLOW_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = "*"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if allowedOrigin != "*" {
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}
