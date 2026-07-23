package integrations

import (
	"encoding/json"
	"testing"
)

func TestDiscordIntegrationKindAndRedaction(t *testing.T) {
	if !validKind(KindDiscord) {
		t.Fatal("discord must be accepted as an integration kind")
	}
	raw := RedactedConfig(KindDiscord, json.RawMessage(`{"webhook_url":"https://example.com/hook","username":"watcher"}`))
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if config["webhook_url"] != "***" {
		t.Fatalf("webhook_url was not redacted: %v", config["webhook_url"])
	}
	if config["username"] != "watcher" {
		t.Fatalf("username changed during redaction: %v", config["username"])
	}
}
