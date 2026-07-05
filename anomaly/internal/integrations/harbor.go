package integrations

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

type harborClient struct {
	cfg HarborConfig
	hc  *http.Client
}

func newHarbor(cfg HarborConfig) *harborClient {
	return &harborClient{cfg: cfg, hc: secureHTTPClient(10 * time.Second)}
}

func (h *harborClient) Test(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		trimSlash(h.cfg.URL)+"/api/v2.0/users/current", nil)
	if err != nil {
		return err
	}
	if h.cfg.Username != "" {
		req.SetBasicAuth(h.cfg.Username, h.cfg.Token)
	} else {
		req.Header.Set("Authorization", "Bearer "+h.cfg.Token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("harbor: unauthorized — check token/username")
	}
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("harbor: %d %s", resp.StatusCode, string(buf))
	}
	return nil
}
