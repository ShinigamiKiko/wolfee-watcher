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

type discordClient struct {
	cfg DiscordConfig
	hc  *http.Client
}

func newDiscord(cfg DiscordConfig) *discordClient {
	return &discordClient{cfg: cfg, hc: secureHTTPClient(10 * time.Second)}
}

func (d *discordClient) Test(ctx context.Context) error {
	payload := map[string]any{
		"content": "Wolfee-Watcher connectivity test — integration configured successfully.",
		"allowed_mentions": map[string]any{
			"parse": []string{},
		},
	}
	if d.cfg.Username != "" {
		payload["username"] = d.cfg.Username
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("discord: %d %s", resp.StatusCode, string(buf))
	}
	return nil
}
