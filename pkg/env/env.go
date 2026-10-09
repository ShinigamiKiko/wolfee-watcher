// Package env reads configuration from environment variables with defaults.
package env

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const HoneypotRetentionKey = "HONEYPOT_EVENT_RETENTION_DAYS"

const HoneypotRetentionDefaultDays = 30

func Str(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func Days(key string, def int) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || n < 1 {
		n = def
	}
	return time.Duration(n) * 24 * time.Hour
}

func HoneypotRetention() time.Duration {
	return Days(HoneypotRetentionKey, HoneypotRetentionDefaultDays)
}
