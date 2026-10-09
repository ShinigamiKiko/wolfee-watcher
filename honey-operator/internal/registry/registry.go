package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Record struct {
	ID          string            `json:"id"`
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Service     string            `json:"service"`
	Port        int32             `json:"port"`
	TargetPort  int32             `json:"targetPort"`
	WorkloadUID string            `json:"workloadUid"`
	ServiceUID  string            `json:"serviceUid"`
	PolicyUID   string            `json:"policyUid"`
	ClusterIP   string            `json:"clusterIP"`
	Selector    map[string]string `json:"selector"`
	Image       string            `json:"image"`
	CreatedBy   string            `json:"createdBy"`
	CreatedAt   time.Time         `json:"createdAt"`
}

var ErrUnavailable = errors.New("honeypot registry is not configured")

type Client struct {
	base   string
	secret string
	http   *http.Client
}

func New(pushURL, secret string) *Client {
	return &Client{
		base:   strings.TrimRight(pushURL, "/"),
		secret: secret,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) Enabled() bool { return c != nil && c.base != "" }

func (c *Client) Register(ctx context.Context, rec Record) error {
	return c.post(ctx, map[string]any{"op": "register", "record": rec})
}

func (c *Client) Unregister(ctx context.Context, id string) error {
	return c.post(ctx, map[string]any{"op": "unregister", "id": id})
}

func (c *Client) List(ctx context.Context) ([]Record, error) {
	if !c.Enabled() {
		return nil, ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/internal/pull/honeypot-registry", nil)
	if err != nil {
		return nil, err
	}
	c.sign(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("registry list: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Items []Record `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) post(ctx context.Context, body any) error {
	if !c.Enabled() {
		return ErrUnavailable
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/internal/push/honeypot-registry", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.sign(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("registry: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (c *Client) sign(req *http.Request) {
	if c.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", c.secret)
	}
	req.Header.Set("X-Cluster-ID", clusterID())
}

func clusterID() string {
	if id := strings.TrimSpace(os.Getenv("CLUSTER_ID")); id != "" {
		return id
	}
	return "default"
}
