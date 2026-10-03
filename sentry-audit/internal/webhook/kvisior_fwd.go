package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	alertspkg "github.com/wolfee-watcher/pkg/alerts"
)

const (
	fwdQueueCap  = 1024
	fwdMaxBatch  = 64
	fwdAttempts  = 4
	fwdBackoff   = 2 * time.Second
	fwdDrainBudg = 10 * time.Second

	pathAuditEvents = "/internal/push/audit"
	pathAuditLog    = "/internal/push/audit-log"
)

type KvisiorForwarder struct {
	pushURL string
	bodyKey string
	secret  string
	client  *http.Client

	q *alertspkg.PushQueue[[]json.RawMessage]
}

func newForwarder(name, pushURL, path, bodyKey, secret string, transport http.RoundTripper) *KvisiorForwarder {
	if pushURL == "" {
		return nil
	}
	f := &KvisiorForwarder{
		pushURL: pushURL + path,
		bodyKey: bodyKey,
		secret:  secret,
		client:  &http.Client{Transport: transport, Timeout: 10 * time.Second},
	}
	f.q = alertspkg.NewPushQueue(name, fwdQueueCap, fwdMaxBatch,
		fwdAttempts, fwdBackoff, fwdDrainBudg, f.deliverBatch)
	return f
}

func NewKvisiorForwarder(pushURL, secret string, transport http.RoundTripper) *KvisiorForwarder {
	return newForwarder("kvisior-fwd/audit", pushURL, pathAuditEvents, "events", secret, transport)
}

func NewLogForwarder(pushURL, secret string, transport http.RoundTripper) *KvisiorForwarder {
	return newForwarder("kvisior-fwd/audit-log", pushURL, pathAuditLog, "records", secret, transport)
}

func (f *KvisiorForwarder) Forward(items []json.RawMessage) {
	if f == nil || len(items) == 0 {
		return
	}
	f.q.Push(items)
}

func (f *KvisiorForwarder) Close() {
	if f == nil {
		return
	}
	f.q.Close()
}

func (f *KvisiorForwarder) deliverBatch(ctx context.Context, batches [][]json.RawMessage) alertspkg.DeliveryResult {
	items := make([]json.RawMessage, 0, len(batches))
	for _, b := range batches {
		items = append(items, b...)
	}
	body, err := json.Marshal(map[string]interface{}{f.bodyKey: items})
	if err != nil {
		f.q.LogErrOnce("marshal failed for %d item(s): %v", len(items), err)
		return alertspkg.DeliveryPermanent
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, f.pushURL, bytes.NewReader(body))
	if err != nil {
		f.q.LogErrOnce("build request failed for %d item(s): %v", len(items), err)
		return alertspkg.DeliveryPermanent
	}
	req.Header.Set("Content-Type", "application/json")
	if f.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", f.secret)
		req.Header.Set("X-Cluster-ID", clusterID())
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.q.LogErrOnce("push failed: %v", err)
		return alertspkg.DeliveryRetry
	}

	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	result := alertspkg.ClassifyHTTPStatus(resp.StatusCode)
	if result != alertspkg.DeliveryOK {
		f.q.LogErrOnce("kvisior responded %d (%s)", resp.StatusCode, result)
	}
	return result
}

func clusterID() string {
	id := strings.TrimSpace(os.Getenv("CLUSTER_ID"))
	if id == "" {
		return "default"
	}
	return id
}
