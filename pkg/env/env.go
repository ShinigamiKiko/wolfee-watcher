// Package env reads configuration from environment variables with defaults.
package env

import "os"

func Str(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
