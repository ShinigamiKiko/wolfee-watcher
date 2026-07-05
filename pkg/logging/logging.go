// Package logging configures the global slog logger to emit ECS-style JSON (or
// text) for log shippers such as Elastic. Controlled by LOG_LEVEL and
// LOG_FORMAT; see docs/logging.md.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

func Setup(service string) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:       level(os.Getenv("LOG_LEVEL")),
		ReplaceAttr: ecsAttr,
	}

	var h slog.Handler
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "text") {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}

	logger := slog.New(h).With("service.name", service)
	slog.SetDefault(logger) // also redirects the standard log package
	return logger
}

func level(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func ecsAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) != 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		a.Key = "@timestamp"
	case slog.LevelKey:
		a.Key = "log.level"
		if lv, ok := a.Value.Any().(slog.Level); ok {
			a.Value = slog.StringValue(strings.ToLower(lv.String()))
		}
	case slog.MessageKey:
		a.Key = "message"
	}
	return a
}
