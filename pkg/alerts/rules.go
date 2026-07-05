package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type RuleFetcher struct {
	url    string
	secret string
	hc     *http.Client
}

func NewRuleFetcher(detType string) *RuleFetcher {
	base := strings.TrimRight(os.Getenv("KVISIOR_URL"), "/")
	if base == "" {
		return nil
	}
	u := base + "/internal/pull/alert-rules"
	if detType != "" {
		u += "?" + url.Values{"detType": {detType}}.Encode()
	}
	return &RuleFetcher{
		url:    u,
		secret: os.Getenv("INTERNAL_PUSH_SECRET"),
		hc:     &http.Client{Timeout: 5 * time.Second},
	}
}

func (f *RuleFetcher) Fetch(ctx context.Context) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, err
	}
	if f.secret != "" {
		req.Header.Set("X-Internal-Push-Secret", f.secret)
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("kvisior responded %d", resp.StatusCode)
	}
	var body struct {
		Policies []json.RawMessage `json:"policies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Policies, nil
}
