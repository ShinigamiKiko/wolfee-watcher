package central

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type LogLine struct {
	Timestamp string `json:"timestamp"`
	Log       string `json:"log"`
}

type Client struct {
	base   string
	secret string
	hc     *http.Client
}

func New() *Client {
	base := strings.TrimRight(os.Getenv("KVISIOR_URL"), "/")
	if base == "" {
		return nil
	}
	return &Client{
		base:   base,
		secret: os.Getenv("INTERNAL_PUSH_SECRET"),
		hc:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) newReq(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if c.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", c.secret)
	}
	return req, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := c.newReq(ctx, method, path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
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

func (c *Client) PullLogs(ctx context.Context, ns, pod, container string, sinceSeconds int64) ([]LogLine, error) {
	q := url.Values{
		"ns": {ns}, "pod": {pod}, "container": {container},
		"sinceSeconds": {strconv.FormatInt(sinceSeconds, 10)},
	}
	var out struct {
		Lines []LogLine `json:"lines"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/internal/pull/logs?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	return out.Lines, nil
}

func (c *Client) PushSnapshotCache(ctx context.Context, gz []byte, etag string) error {
	req, err := c.newReq(ctx, http.MethodPost,
		"/internal/push/snapshot-cache?"+url.Values{"etag": {etag}}.Encode(), bytes.NewReader(gz))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/gzip")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("kvisior responded %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) PullSnapshotCache(ctx context.Context) ([]byte, string, error) {
	req, err := c.newReq(ctx, http.MethodGet, "/internal/pull/snapshot-cache", nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("kvisior responded %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	return data, resp.Header.Get("X-Snapshot-ETag"), nil
}
