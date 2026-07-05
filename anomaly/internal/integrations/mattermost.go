package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type mattermostClient struct {
	cfg MattermostConfig
	hc  *http.Client
}

func newMattermost(cfg MattermostConfig) *mattermostClient {
	return &mattermostClient{cfg: cfg, hc: secureHTTPClient(10 * time.Second)}
}

func (m *mattermostClient) Post(ctx context.Context, text string) error {
	payload := map[string]any{"text": text}
	if m.cfg.Channel != "" {
		payload["channel"] = m.cfg.Channel
	}
	if m.cfg.Username != "" {
		payload["username"] = m.cfg.Username
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("mattermost: %d %s", resp.StatusCode, string(buf))
	}
	return nil
}

func (m *mattermostClient) Test(ctx context.Context) error {
	return m.Post(ctx, "Kvisior8 connectivity test — integration configured successfully.")
}
