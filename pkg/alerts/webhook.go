package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	WebhookDiscord    = "discord"
	WebhookMattermost = "mattermost"
)

type WebhookConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel,omitempty"`
	Username   string `json:"username,omitempty"`
}

func NewWebhookHTTPClient(timeout time.Duration) *http.Client {
	policy := loadWebhookDialPolicy()
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	dialer.Control = func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("webhook SSRF guard: unresolved address %s", address)
		}
		if !policy.permits(ip) {
			return fmt.Errorf("webhook SSRF guard: refusing non-public address %s", address)
		}
		return nil
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		},
	}
}

func SendWebhook(ctx context.Context, hc *http.Client, kind string, cfg WebhookConfig, alert AlertLog) error {
	if hc == nil {
		return fmt.Errorf("webhook: HTTP client is required")
	}
	if err := validateWebhookURL(cfg.WebhookURL); err != nil {
		return err
	}
	payload, err := webhookPayload(kind, cfg, alert)
	if err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s webhook: %w", kind, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s webhook: HTTP %d: %s", kind, resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	return nil
}

func webhookPayload(kind string, cfg WebhookConfig, alert AlertLog) (map[string]any, error) {
	severity := strings.ToUpper(strings.TrimSpace(alert.Severity))
	name := firstNonEmpty(alert.RuleName, alert.RuleID, alert.DetType, "Security alert")
	if severity == "" {
		text := "🔔 **Wolfee-Watcher notification**\n" + safeText(summary(alert, name), 1800)
		if kind == WebhookDiscord {
			payload := map[string]any{
				"content":          text,
				"allowed_mentions": map[string]any{"parse": []string{}},
			}
			if cfg.Username != "" {
				payload["username"] = cfg.Username
			}
			return payload, nil
		}
		if kind == WebhookMattermost {
			payload := map[string]any{"text": text}
			applyMattermostOverrides(payload, cfg)
			return payload, nil
		}
		return nil, fmt.Errorf("unsupported webhook kind %q", kind)
	}

	fields := alertFields(alert)
	description := safeText(alert.Detail, 3500)
	title := fmt.Sprintf("🚨 %s · %s", severity, safeText(name, 180))
	if kind == WebhookDiscord {
		discordFields := make([]map[string]any, 0, len(fields))
		for _, field := range fields {
			discordFields = append(discordFields, map[string]any{
				"name": field.name, "value": field.value, "inline": true,
			})
		}
		embed := map[string]any{
			"title":  title,
			"color":  severityColor(severity),
			"fields": discordFields,
			"footer": map[string]any{"text": "Wolfee-Watcher"},
		}
		if description != "" {
			embed["description"] = description
		}
		if !alert.Timestamp.IsZero() {
			embed["timestamp"] = alert.Timestamp.UTC().Format(time.RFC3339)
		}
		payload := map[string]any{
			"embeds":           []map[string]any{embed},
			"allowed_mentions": map[string]any{"parse": []string{}},
		}
		if cfg.Username != "" {
			payload["username"] = cfg.Username
		}
		return payload, nil
	}
	if kind == WebhookMattermost {
		mattermostFields := make([]map[string]any, 0, len(fields))
		for _, field := range fields {
			mattermostFields = append(mattermostFields, map[string]any{
				"title": field.name, "value": field.value, "short": true,
			})
		}
		attachment := map[string]any{
			"fallback": title,
			"color":    fmt.Sprintf("#%06x", severityColor(severity)),
			"title":    title,
			"fields":   mattermostFields,
			"footer":   "Wolfee-Watcher",
		}
		if description != "" {
			attachment["text"] = description
		}
		payload := map[string]any{"attachments": []map[string]any{attachment}}
		applyMattermostOverrides(payload, cfg)
		return payload, nil
	}
	return nil, fmt.Errorf("unsupported webhook kind %q", kind)
}

type webhookField struct {
	name  string
	value string
}

func alertFields(alert AlertLog) []webhookField {
	fields := make([]webhookField, 0, 5)
	add := func(name, value string) {
		if value = strings.TrimSpace(value); value != "" {
			fields = append(fields, webhookField{name: name, value: safeText(value, 900)})
		}
	}
	add("Source", alert.Source)
	add("Type", alert.DetType)
	location := alert.Namespace
	if alert.Target != "" {
		if location != "" {
			location += " / "
		}
		location += alert.Target
	}
	add("Namespace / target", location)
	add("Syscall", alert.Syscall)
	return fields
}

func summary(alert AlertLog, name string) string {
	parts := []string{name}
	if alert.Source != "" {
		parts = append(parts, "from "+alert.Source)
	}
	if alert.Namespace != "" || alert.Target != "" {
		location := strings.Trim(strings.TrimSpace(alert.Namespace)+" / "+strings.TrimSpace(alert.Target), " / ")
		parts = append(parts, "at "+location)
	}
	if alert.Detail != "" {
		parts = append(parts, alert.Detail)
	}
	return strings.Join(parts, " — ")
}

func applyMattermostOverrides(payload map[string]any, cfg WebhookConfig) {
	if cfg.Channel != "" {
		payload["channel"] = cfg.Channel
	}
	if cfg.Username != "" {
		payload["username"] = cfg.Username
	}
}

func safeText(value string, limit int) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "@", "@\u200b")
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit-1]) + "…"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func severityColor(severity string) int {
	switch severity {
	case "CRITICAL":
		return 0xd32f2f
	case "HIGH":
		return 0xf57c00
	case "MEDIUM":
		return 0xfbc02d
	case "LOW":
		return 0x388e3c
	default:
		return 0x607d8b
	}
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("webhook URL must use http or https")
	}
	if u.User != nil {
		return fmt.Errorf("webhook URL must not contain user information")
	}
	return nil
}

type webhookDialPolicy struct {
	allowAll bool
	allowed  []*net.IPNet
}

func loadWebhookDialPolicy() webhookDialPolicy {
	var policy webhookDialPolicy
	switch strings.ToLower(strings.TrimSpace(os.Getenv("INTEGRATIONS_ALLOW_INTERNAL"))) {
	case "1", "true", "yes", "on":
		policy.allowAll = true
	}
	for _, cidr := range strings.Split(os.Getenv("INTEGRATIONS_ALLOWED_CIDRS"), ",") {
		if cidr = strings.TrimSpace(cidr); cidr == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			policy.allowed = append(policy.allowed, network)
		}
	}
	return policy
}

func (policy webhookDialPolicy) permits(ip net.IP) bool {
	if isPublicWebhookIP(ip) {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || isMetadataIP(ip) {
		return false
	}
	if policy.allowAll {
		return true
	}
	for _, network := range policy.allowed {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isPublicWebhookIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false
	}
	return true
}

func isMetadataIP(ip net.IP) bool {
	return ip.Equal(net.ParseIP("169.254.169.254")) ||
		ip.Equal(net.ParseIP("100.100.100.200")) ||
		ip.Equal(net.ParseIP("fd00:ec2::254"))
}
