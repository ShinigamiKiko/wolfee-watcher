package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/store"
)

type alertLogReq struct {
	DetType   string `json:"detType"`
	Source    string `json:"source"`
	RuleID    string `json:"ruleId,omitempty"`
	RuleName  string `json:"ruleName"`
	Severity  string `json:"severity,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Target    string `json:"target,omitempty"`
	Syscall   string `json:"syscall,omitempty"`
	Detail    string `json:"detail,omitempty"`

	Persist     bool            `json:"persist,omitempty"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
}

func makeAlertLogHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handleAlertLog(st, w, r)
	}
}

func handleAlertLog(st *store.Store, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var wrapper struct {
		Alerts []alertLogReq `json:"alerts"`
	}
	alerts := wrapper.Alerts
	if err := json.Unmarshal(body, &wrapper); err != nil || len(wrapper.Alerts) == 0 {
		var single alertLogReq
		if err := json.Unmarshal(body, &single); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		alerts = []alertLogReq{single}
	} else {
		alerts = wrapper.Alerts
	}

	persist := make([]store.IncomingAlert, 0, len(alerts))
	for _, req := range alerts {
		logAlert(req)
		if req.Persist {
			persist = append(persist, store.IncomingAlert{
				Source: req.Source, DetType: req.DetType,
				RuleID: req.RuleID, RuleName: req.RuleName, Severity: req.Severity,
				Namespace: req.Namespace, Target: req.Target, Syscall: req.Syscall,
				Detail: req.Detail, Fingerprint: req.Fingerprint, Data: req.Data,
			})
		}
	}
	if len(persist) > 0 {
		if st == nil {
			log.Printf("[alert-log] persist requested for %d alert(s) but postgres not configured — not stored", len(persist))
		} else {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			if err := st.InsertAlerts(ctx, persist); err != nil {
				log.Printf("[alert-log] persist %d alert(s): %v", len(persist), err)
				http.Error(w, `{"error":"persist failed"}`, http.StatusInternalServerError)
				return
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func logAlert(req alertLogReq) {
	detType := strings.ToLower(req.DetType)
	if detType == "" {
		detType = "alert"
	}
	name := req.RuleName
	if name == "" {
		name = req.RuleID
	}
	sev := strings.ToUpper(req.Severity)

	attrs := []slog.Attr{
		slog.String("component", "kvisior/alert-log"),
		slog.String("event.kind", "alert"),
		slog.String("alert.type", detType),
		slog.String("alert.source", req.Source),
	}
	appendIf := func(key, val string) {
		if val != "" {
			attrs = append(attrs, slog.String(key, val))
		}
	}
	appendIf("rule.name", name)
	appendIf("rule.id", req.RuleID)
	appendIf("alert.severity", sev)
	appendIf("namespace", req.Namespace)
	appendIf("target", req.Target)
	appendIf("syscall", req.Syscall)
	appendIf("detail", req.Detail)
	appendIf("alert.fingerprint", req.Fingerprint)

	slog.LogAttrs(context.Background(), alertLevel(sev), "security_alert", attrs...)
}

func alertLevel(sev string) slog.Level {
	switch sev {
	case "CRITICAL", "HIGH":
		return slog.LevelError
	case "LOW", "INFO", "INFORMATIONAL":
		return slog.LevelInfo
	default:
		return slog.LevelWarn
	}
}
