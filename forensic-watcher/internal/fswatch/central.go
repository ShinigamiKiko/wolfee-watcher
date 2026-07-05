package fswatch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type CentralClient struct {
	base   string
	secret string
	hc     *http.Client
}

func NewCentralClient() *CentralClient {
	base := strings.TrimRight(os.Getenv("KVISIOR_URL"), "/")
	if base == "" {
		return nil
	}
	return &CentralClient{
		base:   base,
		secret: os.Getenv("INTERNAL_PUSH_SECRET"),
		hc:     &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *CentralClient) do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", c.secret)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("kvisior responded %d", resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *CentralClient) PushEvents(ctx context.Context, ns, pod string, entries []FileEntry) error {
	return c.do(ctx, http.MethodPost, "/internal/push/forensic", map[string]interface{}{
		"ns": ns, "pod": pod, "entries": entries,
	}, nil)
}

func (c *CentralClient) UpsertWatch(ctx context.Context, ns, pod string) error {
	return c.do(ctx, http.MethodPost, "/internal/push/forensic-watch?"+nsPodQuery(ns, pod), nil, nil)
}

func (c *CentralClient) DeleteWatch(ctx context.Context, ns, pod string) error {
	return c.do(ctx, http.MethodDelete, "/internal/push/forensic-watch?"+nsPodQuery(ns, pod), nil, nil)
}

func (c *CentralClient) PullDiff(ctx context.Context, ns, pod string) ([]FileEntry, error) {
	var out struct {
		Entries []FileEntry `json:"entries"`
	}
	if err := c.do(ctx, http.MethodGet, "/internal/pull/forensic?"+nsPodQuery(ns, pod), nil, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

func nsPodQuery(ns, pod string) string {
	return url.Values{"ns": {ns}, "pod": {pod}}.Encode()
}

type LogEntry struct {
	Ts  time.Time `json:"ts"`
	Log string    `json:"log"`
}

func (c *CentralClient) PushLogEntries(ctx context.Context, node, ns, pod, container string, entries []LogEntry) error {
	return c.do(ctx, http.MethodPost, "/internal/push/logs", map[string]interface{}{
		"node": node, "ns": ns, "pod": pod, "container": container, "entries": entries,
	}, nil)
}

func (c *CentralClient) PullLogCursors(ctx context.Context, node string) (map[string]time.Time, error) {
	var out struct {
		Cursors map[string]time.Time `json:"cursors"`
	}
	q := url.Values{"node": {node}}.Encode()
	if err := c.do(ctx, http.MethodGet, "/internal/pull/log-cursors?"+q, nil, &out); err != nil {
		return nil, err
	}
	return out.Cursors, nil
}
