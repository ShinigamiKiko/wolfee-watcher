package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

const maxResultForwards = 16

type kvClient struct {
	base   string
	secret string
	hc     *http.Client
	sem    chan struct{}

	errMu  sync.Mutex
	lastEr time.Time
}

func newKVClient() *kvClient {
	base := strings.TrimRight(os.Getenv("KVISIOR_URL"), "/")
	if base == "" {
		return &kvClient{}
	}
	return &kvClient{
		base:   base,
		secret: os.Getenv("INTERNAL_PUSH_SECRET"),
		hc:     &http.Client{Timeout: 10 * time.Second},
		sem:    make(chan struct{}, maxResultForwards),
	}
}

func (c *kvClient) enabled() bool { return c != nil && c.base != "" }

func (c *kvClient) postAsync(path, label string, body []byte) {
	if !c.enabled() {
		return
	}
	select {
	case c.sem <- struct{}{}:
	default:
		c.logErrOnce("forward pool full, dropping %s", label)
		return
	}
	go func() {
		defer func() { <-c.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if c.secret != "" {
			req.Header.Set("X-Internal-Push-Secret", c.secret)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			c.logErrOnce("post %s: %v", label, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			c.logErrOnce("kvisior %d for %s", resp.StatusCode, label)
		}
	}()
}

func (c *kvClient) PushResult(res *internal.ScanResult) {
	if !c.enabled() || res == nil {
		return
	}
	body, err := json.Marshal(res)
	if err != nil {
		return
	}
	c.postAsync("/internal/push/scan", "result "+res.Image, body)
}

func (c *kvClient) PushHistories(list []internal.ImageHistory) {
	if !c.enabled() {
		return
	}
	body, err := json.Marshal(map[string]interface{}{"histories": list})
	if err != nil {
		return
	}
	c.postAsync("/internal/push/histories", "histories", body)
}

func (c *kvClient) PushScannerState(key string, v interface{}) {
	if !c.enabled() {
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	body, err := json.Marshal(struct {
		Key  string          `json:"key"`
		Data json.RawMessage `json:"data"`
	}{Key: key, Data: data})
	if err != nil {
		return
	}
	c.postAsync("/internal/push/scanner-state", "state "+key, body)
}

func (c *kvClient) PullScannerState(key string, out interface{}) bool {
	if !c.enabled() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u := c.base + "/internal/pull/scanner-state?key=" + url.QueryEscape(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	if c.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", c.secret)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.logErrOnce("pull %s: %v", key, err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false
	}
	if resp.StatusCode >= 400 {
		c.logErrOnce("pull %s: %d", key, resp.StatusCode)
		return false
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		c.logErrOnce("pull %s decode: %v", key, err)
		return false
	}
	return true
}

func (c *kvClient) logErrOnce(format string, args ...interface{}) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if time.Since(c.lastEr) < time.Minute {
		return
	}
	c.lastEr = time.Now()
	log.Printf("[kv-sync] "+format, args...)
}
