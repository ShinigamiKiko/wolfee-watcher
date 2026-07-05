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

type jiraClient struct {
	cfg JiraConfig
	hc  *http.Client
}

func newJira(cfg JiraConfig) *jiraClient {
	return &jiraClient{cfg: cfg, hc: secureHTTPClient(10 * time.Second)}
}

func (j *jiraClient) auth(req *http.Request) {
	if j.cfg.Email != "" {
		req.SetBasicAuth(j.cfg.Email, j.cfg.Token)
	} else {
		req.Header.Set("Authorization", "Bearer "+j.cfg.Token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
}

func (j *jiraClient) Test(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trimSlash(j.cfg.URL)+"/rest/api/2/myself", nil)
	if err != nil {
		return err
	}
	j.auth(req)
	resp, err := j.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("jira: %d %s", resp.StatusCode, string(body))
	}
	return nil
}

func (j *jiraClient) CreateIssue(ctx context.Context, title, description string) error {
	issueType := j.cfg.IssueType
	if issueType == "" {
		issueType = "Task"
	}
	payload := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": j.cfg.ProjectID},
			"summary":     "Attention: " + title,
			"description": description,
			"issuetype":   map[string]string{"name": issueType},
		},
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		trimSlash(j.cfg.URL)+"/rest/api/2/issue", bytes.NewReader(body))
	if err != nil {
		return err
	}
	j.auth(req)
	resp, err := j.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("jira create: %d %s", resp.StatusCode, string(buf))
	}
	return nil
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
