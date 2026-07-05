package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type EventInfo struct {
	ID        string
	Ts        time.Time
	Kind      string
	Namespace string
	Workload  string
	Pod       string
	Process   string
	Detail    string
	DstIP     string
	DstPort   uint32
	Syscall   string
}

type Manager struct {
	store *Store
}

func NewManager(store *Store) *Manager {
	return &Manager{store: store}
}

func (m *Manager) Dispatch(ev EventInfo) {
	_ = ev
}

func (m *Manager) Test(ctx context.Context, kind string, raw json.RawMessage) error {
	switch kind {
	case KindJira:
		var c JiraConfig
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("invalid jira config: %w", err)
		}
		if c.URL == "" || c.Token == "" || c.ProjectID == "" {
			return fmt.Errorf("url, token and project are required")
		}
		return newJira(c).Test(ctx)
	case KindMattermost:
		var c MattermostConfig
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("invalid mattermost config: %w", err)
		}
		if c.WebhookURL == "" {
			return fmt.Errorf("webhook_url is required")
		}
		return newMattermost(c).Test(ctx)
	case KindHarbor:
		var c HarborConfig
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("invalid harbor config: %w", err)
		}
		if c.URL == "" || c.Token == "" {
			return fmt.Errorf("url and token are required")
		}
		return newHarbor(c).Test(ctx)
	default:
		return fmt.Errorf("unknown kind %q", kind)
	}
}
