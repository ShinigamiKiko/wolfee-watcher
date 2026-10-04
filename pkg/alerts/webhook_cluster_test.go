package alerts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

func TestWebhookClusterContextForBothDestinations(t *testing.T) {
	for _, kind := range []string{WebhookDiscord, WebhookMattermost} {
		for _, severity := range []string{"HIGH", ""} {
			t.Run(kind+"/"+severity, func(t *testing.T) {
				for _, cluster := range []string{"prod-eu", "prod-us"} {
					alert := AlertLog{
						ID: 42, ClusterID: cluster, ClusterName: "Production",
						Timestamp: time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC),
						Source: "tracee-bridge", DetType: "Runtime", RuleID: "shell",
						RuleName: "Shell spawned", Severity: severity,
						Namespace: "prod", Target: "api-123", Syscall: "execve",
						Detail: "unexpected shell",
						Data: json.RawMessage(`{"src_ip":"private-address","user":"private-actor","node":"private-node"}`),
					}
					payload, err := webhookPayload(kind, WebhookConfig{}, alert)
					if err != nil {
						t.Fatal(err)
					}
					raw, err := json.Marshal(payload)
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{
						"Production (" + cluster + ")", cluster, "42",
						"2026-10-04T09:00:00Z", "tracee-bridge", "shell", "prod / api-123",
					} {
						if !strings.Contains(string(raw), want) {
							t.Errorf("notification is missing %q: %s", want, raw)
						}
					}
					for _, private := range []string{"private-address", "private-actor", "private-node"} {
						if strings.Contains(string(raw), private) {
							t.Errorf("raw metadata was added to external notification: %s", raw)
						}
					}
				}
			})
		}
	}
}

func TestWebhookUnknownClusterKeepsStableID(t *testing.T) {
	fields := alertFields(AlertLog{ClusterID: "new-cluster"})
	if fields[0].name != "Cluster" || fields[0].value != "new-cluster" {
		t.Fatalf("unregistered cluster = %#v", fields)
	}
	if got := (AlertLog{}).ClusterLabel(); got != "default" {
		t.Fatalf("legacy cluster label = %q", got)
	}
}

func TestDiscordEnrichedPayloadStaysWithinEmbedLimits(t *testing.T) {
	long := strings.Repeat("🚨@everyone", 1000)
	alert := AlertLog{
		ID: 42, ClusterID: "prod-eu", ClusterName: long,
		Timestamp: time.Now(), Source: long, DetType: long, RuleID: long,
		RuleName: long, Severity: "HIGH", Namespace: long, Target: long,
		Syscall: long, Detail: long,
	}
	payload, err := webhookPayload(WebhookDiscord, WebhookConfig{}, alert)
	if err != nil {
		t.Fatal(err)
	}
	embed := payload["embeds"].([]map[string]any)[0]
	length := func(s string) int { return len(utf16.Encode([]rune(s))) }
	title := embed["title"].(string)
	description, _ := embed["description"].(string)
	total := length(title) + length(description) + length(embed["footer"].(map[string]any)["text"].(string))
	if length(title) > 256 || length(description) > 4096 || !utf8.ValidString(description) {
		t.Fatalf("invalid title or description sizes: %d / %d", length(title), length(description))
	}
	fields := embed["fields"].([]map[string]any)
	if len(fields) > 25 {
		t.Fatalf("too many fields: %d", len(fields))
	}
	foundID := false
	for _, field := range fields {
		name, value := field["name"].(string), field["value"].(string)
		if length(name) > 256 || length(value) > 1024 || !utf8.ValidString(value) {
			t.Fatalf("invalid field %q", name)
		}
		total += length(name) + length(value)
		if name == "Cluster ID" && value == "prod-eu" {
			foundID = true
		}
	}
	if total > 6000 || !foundID {
		t.Fatalf("embed length = %d, stable cluster ID visible = %v", total, foundID)
	}
}

func TestSafeTextHandlesEmptyBudget(t *testing.T) {
	for _, limit := range []int{-1, 0} {
		if got := safeText("alert", limit); got != "" {
			t.Fatalf("safeText with budget %d = %q", limit, got)
		}
	}
}
