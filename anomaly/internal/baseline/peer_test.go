package baseline

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPeerTextMarshalRoundTrip(t *testing.T) {
	p := Peer{
		IsIngress: true,
		DstPort:   443,
		Protocol:  TCP,
		CidrBlock: "10.0.0.0/24",
		Entity: Entity{
			ID:         "default/web",
			Type:       EntityDeployment,
			Name:       "web",
			Discovered: false,
		},
	}
	text, err := p.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if len(text) == 0 {
		t.Fatal("MarshalText produced empty output")
	}
	var out Peer
	if err := out.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if out != p {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", out, p)
	}
}

func TestBaselineInfoJSONRoundTrip(t *testing.T) {
	original := &BaselineInfo{
		Namespace:            "default",
		DeploymentName:       "web",
		DeploymentID:         "abc",
		ObservationPeriodEnd: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UserLocked:           true,
		BaselinePeers: map[Peer]struct{}{
			{IsIngress: true, DstPort: 443, Protocol: TCP,
				Entity: Entity{ID: "default/web", Type: EntityDeployment, Name: "web"}}: {},
			{IsIngress: false, DstPort: 5432, Protocol: TCP,
				Entity:    Entity{ID: "10.0.0.0/24", Type: EntityExternalSource, Name: "10.0.0.0/24"},
				CidrBlock: "10.0.0.0/24"}: {},
		},
		ForbiddenPeers: map[Peer]struct{}{
			{IsIngress: true, DstPort: 22, Protocol: TCP}: {},
		},
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed (this is the bug we're fixing): %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("Marshal produced empty bytes")
	}
	var restored BaselineInfo
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(restored.BaselinePeers) != len(original.BaselinePeers) {
		t.Errorf("BaselinePeers size mismatch: got %d want %d",
			len(restored.BaselinePeers), len(original.BaselinePeers))
	}
	for p := range original.BaselinePeers {
		if _, ok := restored.BaselinePeers[p]; !ok {
			t.Errorf("BaselinePeers missing peer after round-trip: %+v", p)
		}
	}
	for p := range original.ForbiddenPeers {
		if _, ok := restored.ForbiddenPeers[p]; !ok {
			t.Errorf("ForbiddenPeers missing peer after round-trip: %+v", p)
		}
	}
	if restored.UserLocked != original.UserLocked {
		t.Errorf("UserLocked mismatch")
	}
	if !restored.ObservationPeriodEnd.Equal(original.ObservationPeriodEnd) {
		t.Errorf("ObservationPeriodEnd mismatch: %v vs %v",
			restored.ObservationPeriodEnd, original.ObservationPeriodEnd)
	}
}
