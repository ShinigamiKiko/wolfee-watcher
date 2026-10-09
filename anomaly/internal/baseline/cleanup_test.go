package baseline

import (
	"testing"
	"time"

	"github.com/wolfee-watcher/pkg/env"
)

func TestAnomalyEventRetentionIsFourteenDays(t *testing.T) {
	if AnomalyEventTTL != 14*24*time.Hour {
		t.Fatalf("AnomalyEventTTL = %s", AnomalyEventTTL)
	}
}

func TestHoneypotProbeRetentionFollowsHoneypotEvents(t *testing.T) {
	if HoneypotProbeTTL != env.HoneypotRetention() {
		t.Fatalf("HoneypotProbeTTL = %s, honeypot events keep %s", HoneypotProbeTTL, env.HoneypotRetention())
	}
	t.Setenv(env.HoneypotRetentionKey, "")
	if got := env.HoneypotRetention(); got != 30*24*time.Hour {
		t.Fatalf("default honeypot retention = %s", got)
	}
	t.Setenv(env.HoneypotRetentionKey, "45")
	if got := env.HoneypotRetention(); got != 45*24*time.Hour {
		t.Fatalf("honeypot retention with 45 days = %s", got)
	}
	t.Setenv(env.HoneypotRetentionKey, "0")
	if got := env.HoneypotRetention(); got != 30*24*time.Hour {
		t.Fatalf("honeypot retention with 0 days = %s", got)
	}
}
