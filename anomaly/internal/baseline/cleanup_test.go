package baseline

import (
	"testing"
	"time"
)

func TestAnomalyEventRetentionIsFourteenDays(t *testing.T) {
	if AnomalyEventTTL != 14*24*time.Hour {
		t.Fatalf("AnomalyEventTTL = %s", AnomalyEventTTL)
	}
}
