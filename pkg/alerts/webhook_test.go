package alerts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDiscordSeverityPayload(t *testing.T) {
	payload, err := webhookPayload(WebhookDiscord, WebhookConfig{Username: "watcher"}, AlertLog{
		Timestamp: time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC),
		Source:    "tracee-bridge", DetType: "Runtime", RuleName: "Shell spawned",
		Severity: "high", Namespace: "prod", Target: "api-123", Syscall: "execve",
		Detail: "unexpected shell",
	})
	if err != nil {
		t.Fatal(err)
	}
	if payload["username"] != "watcher" {
		t.Fatalf("username = %v", payload["username"])
	}
	embeds, ok := payload["embeds"].([]map[string]any)
	if !ok || len(embeds) != 1 {
		t.Fatalf("embeds = %#v", payload["embeds"])
	}
	if title, _ := embeds[0]["title"].(string); !strings.Contains(title, "HIGH") || !strings.Contains(title, "Shell spawned") {
		t.Fatalf("title = %q", title)
	}
	fields, ok := embeds[0]["fields"].([]map[string]any)
	if !ok || len(fields) < 3 {
		t.Fatalf("fields = %#v", embeds[0]["fields"])
	}
}

func TestMissingSeverityUsesSimpleNotification(t *testing.T) {
	for _, kind := range []string{WebhookDiscord, WebhookMattermost} {
		t.Run(kind, func(t *testing.T) {
			payload, err := webhookPayload(kind, WebhookConfig{}, AlertLog{
				Source: "sensor", RuleName: "Configuration changed",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := payload["embeds"]; exists {
				t.Fatal("severity-less notification must not contain embeds")
			}
			if _, exists := payload["attachments"]; exists {
				t.Fatal("severity-less notification must not contain attachments")
			}
			text, _ := payload["content"].(string)
			if text == "" {
				text, _ = payload["text"].(string)
			}
			if !strings.Contains(text, "Configuration changed") {
				t.Fatalf("notification = %q", text)
			}
		})
	}
}

func TestPayloadSuppressesMentions(t *testing.T) {
	payload, err := webhookPayload(WebhookDiscord, WebhookConfig{}, AlertLog{
		RuleName: "@everyone", Severity: "critical",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"@everyone"`) {
		t.Fatalf("mention was not neutralized: %s", raw)
	}
}

func TestWebhookRetryBackoffCapsAtOneHour(t *testing.T) {
	if got := webhookRetryBackoff(1); got != time.Minute {
		t.Fatalf("first retry = %s", got)
	}
	if got := webhookRetryBackoff(20); got != time.Hour {
		t.Fatalf("capped retry = %s", got)
	}
}

func TestAlertRetentionIsFourteenDays(t *testing.T) {
	if AlertsTTL != 14*24*time.Hour {
		t.Fatalf("AlertsTTL = %s", AlertsTTL)
	}
}
