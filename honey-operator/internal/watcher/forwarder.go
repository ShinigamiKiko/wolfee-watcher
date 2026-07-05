package watcher

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

type kvisiorForwarder struct {
	pushURL string
	secret  string
	client  *http.Client

	q *alertspkg.PushQueue[json.RawMessage]
}

func newKvisiorForwarder(pushURL, secret string) *kvisiorForwarder {
	if pushURL == "" {
		return nil
	}
	f := &kvisiorForwarder{
		pushURL: pushURL + "/internal/push/honeypot",
		secret:  secret,
		client:  &http.Client{Timeout: 5 * time.Second},
	}
	f.q = alertspkg.NewPushQueue("honey-fwd", fwdQueueCap, fwdMaxBatch,
		fwdAttempts, fwdBackoff, fwdDrainBudg, f.deliverBatch)
	return f
}

func (f *kvisiorForwarder) forward(payload []byte) {
	if f == nil {
		return
	}
	f.q.Push(json.RawMessage(payload))
}

func (f *kvisiorForwarder) close() {
	if f == nil {
		return
	}
	f.q.Close()
}

func (f *kvisiorForwarder) deliverBatch(ctx context.Context, batch []json.RawMessage) bool {
	body, err := json.Marshal(map[string]interface{}{"events": batch})
	if err != nil {
		f.q.LogErrOnce("marshal failed, dropping %d event(s): %v", len(batch), err)
		return true
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, f.pushURL, bytes.NewReader(body))
	if err != nil {
		f.q.LogErrOnce("build request failed, dropping %d event(s): %v", len(batch), err)
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
