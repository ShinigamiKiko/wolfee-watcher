package kv

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxInFlight = 8

type AuditRun struct {
	Tool      string      `json:"tool"`
	RunID     string      `json:"runId"`
	Status    string      `json:"status"`
	StartedAt time.Time   `json:"startedAt,omitempty"`
	DoneAt    time.Time   `json:"doneAt,omitempty"`
	Parsed    interface{} `json:"parsed"`
	Error     string      `json:"error,omitempty"`
}

type Client struct {
	base   string
	secret string
	hc     *http.Client
	sem    chan struct{}

	errMu  sync.Mutex
	lastEr time.Time
}

func New(base, secret string) *Client {
	base = strings.TrimRight(base, "/")
	if base == "" {
		return &Client{}
	}
	return &Client{
		base:   base,
		secret: secret,
		hc:     &http.Client{Timeout: 10 * time.Second},
		sem:    make(chan struct{}, maxInFlight),
	}
}

func (c *Client) enabled() bool { return c != nil && c.base != "" }

func (c *Client) PushAuditRun(run AuditRun) {
	if !c.enabled() {
		return
	}
	body, err := json.Marshal(run)
	if err != nil {
		return
	}
	select {
	case c.sem <- struct{}{}:
	default:
		c.logErrOnce("forward pool full, dropping audit run %s/%s", run.Tool, run.RunID)
		return
	}
	go func() {
		defer func() { <-c.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/internal/push/audit-run", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if c.secret != "" {
			req.Header.Set("X-Internal-Push-Secret", c.secret)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			c.logErrOnce("push audit run %s/%s: %v", run.Tool, run.RunID, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			c.logErrOnce("kvisior %d for audit run %s/%s", resp.StatusCode, run.Tool, run.RunID)
		}
	}()
}

func (c *Client) logErrOnce(format string, args ...interface{}) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if time.Since(c.lastEr) < time.Minute {
		return
	}
	c.lastEr = time.Now()
	log.Printf("[kv-sync] "+format, args...)
}
