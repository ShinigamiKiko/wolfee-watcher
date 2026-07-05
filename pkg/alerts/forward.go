package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type AlertLog struct {
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

const (
	defaultQueueCap        = 1024
	defaultMaxAlertBatch   = 64
	defaultDeliverAttempts = 4
	defaultDeliverBackoff  = 2 * time.Second
	defaultDrainTimeout    = 10 * time.Second
	defaultHTTPTimeout     = 5 * time.Second
)

type Forwarder struct {
	url    string
	secret string
	hc     *http.Client
	timeout time.Duration

	q *PushQueue[AlertLog]
}

func NewForwarder() *Forwarder {
	base := strings.TrimRight(os.Getenv("KVISIOR_URL"), "/")
	if base == "" {
		return &Forwarder{}
	}
	httpTimeout := envDuration("ALERT_FORWARD_HTTP_TIMEOUT_SEC", defaultHTTPTimeout)
	queueCap := envInt("ALERT_FORWARD_QUEUE_CAP", defaultQueueCap)
	maxBatch := envInt("ALERT_FORWARD_MAX_BATCH", defaultMaxAlertBatch)
	attempts := envInt("ALERT_FORWARD_ATTEMPTS", defaultDeliverAttempts)
	backoff := envDuration("ALERT_FORWARD_BACKOFF_SEC", defaultDeliverBackoff)
	drain := envDuration("ALERT_FORWARD_DRAIN_SEC", defaultDrainTimeout)
	f := &Forwarder{
		url:     base + "/internal/alert-log",
		secret:  os.Getenv("INTERNAL_PUSH_SECRET"),
		hc:      &http.Client{Timeout: httpTimeout},
		timeout: httpTimeout,
	}
	f.q = NewPushQueue("alert-fwd",
		queueCap,
		maxBatch,
		attempts,
		backoff,
		drain,
		f.deliverBatch)
	slog.Info("alert_forwarder_enabled",
		"component", "pkg/alerts/forwarder",
		"url", f.url,
		"queue_capacity", queueCap,
		"max_batch", maxBatch,
		"attempts", attempts,
		"backoff", backoff.String(),
		"drain_timeout", drain.String(),
		"http_timeout", httpTimeout.String(),
		"secret_configured", f.secret != "")
	return f
}

func (f *Forwarder) Send(a AlertLog) {
	if f == nil || f.url == "" {
		return
	}
	f.q.Push(a)
}

func (f *Forwarder) OnDeliveryFailed(fn func(batch []AlertLog)) {
	if f == nil || f.q == nil {
		return
	}
	f.q.OnDrop(fn)
}

func (f *Forwarder) QueueStats() (buffered, capacity int, dropped int64) {
	if f == nil || f.q == nil {
		return 0, 0, 0
	}
	return f.q.Len(), f.q.Cap(), f.q.Dropped()
}

func (f *Forwarder) Close() {
	if f == nil || f.url == "" {
		return
	}
	f.q.Close()
}

func (f *Forwarder) deliverBatch(ctx context.Context, batch []AlertLog) bool {
	body, err := json.Marshal(map[string]interface{}{"alerts": batch})
	if err != nil {
		f.q.LogErrOnce("marshal failed, dropping %d alert(s): %v", len(batch), err)
		return true
	}
	reqCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, f.url, bytes.NewReader(body))
	if err != nil {
		f.q.LogErrOnce("build request failed, dropping %d alert(s): %v", len(batch), err)
		return true
	}
	req.Header.Set("Content-Type", "application/json")
	if f.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", f.secret)
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		f.q.LogErrOnce("post: %v", err)
		return false
	}

	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		f.q.LogErrOnce("kvisior responded %d", resp.StatusCode)
		return resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests
	}
	return true
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		slog.Warn("invalid_int_env",
			"component", "pkg/alerts/forwarder",
			"key", key,
			"value", v,
			"default", def)
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		slog.Warn("invalid_duration_env",
			"component", "pkg/alerts/forwarder",
			"key", key,
			"value", v,
			"default", def.String())
	}
	return def
}
