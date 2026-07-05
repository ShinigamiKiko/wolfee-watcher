package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	alertspkg "github.com/wolfee-watcher/pkg/alerts"
)

const (
	fwdQueueCap  = 1024
	fwdMaxBatch  = 64
	fwdAttempts  = 4
	fwdBackoff   = 2 * time.Second
	fwdDrainBudg = 10 * time.Second
)

type KvisiorForwarder struct {
	pushURL string
	secret  string
	client  *http.Client

	q *alertspkg.PushQueue[[]json.RawMessage]
}

func NewKvisiorForwarder(pushURL, secret string, transport http.RoundTripper) *KvisiorForwarder {
	if pushURL == "" {
		return nil
	}
	f := &KvisiorForwarder{
		pushURL: pushURL + "/internal/push/audit",
		secret:  secret,
		client:  &http.Client{Transport: transport, Timeout: 5 * time.Second},
	}
	f.q = alertspkg.NewPushQueue("kvisior-fwd/audit", fwdQueueCap, fwdMaxBatch,
		fwdAttempts, fwdBackoff, fwdDrainBudg, f.deliverBatch)
	return f
}

func (f *KvisiorForwarder) Forward(events []json.RawMessage) {
	if f == nil || len(events) == 0 {
		return
	}
	f.q.Push(events)
}

func (f *KvisiorForwarder) Close() {
	if f == nil {
		return
	}
	f.q.Close()
}

func (f *KvisiorForwarder) deliverBatch(ctx context.Context, batches [][]json.RawMessage) bool {
	events := make([]json.RawMessage, 0, len(batches))
	for _, b := range batches {
		events = append(events, b...)
	}
	body, err := json.Marshal(map[string]interface{}{"events": events})
	if err != nil {
		f.q.LogErrOnce("marshal failed, dropping %d event(s): %v", len(events), err)
		return true
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, f.pushURL, bytes.NewReader(body))
	if err != nil {
		f.q.LogErrOnce("build request failed, dropping %d event(s): %v", len(events), err)
		return true
	}
	req.Header.Set("Content-Type", "application/json")
	if f.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", f.secret)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.q.LogErrOnce("push failed: %v", err)
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
