package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdmissionDoesNotWaitForOfflineDelivery(t *testing.T) {
	release := make(chan struct{})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer remote.Close()
	defer close(release)
	forwarder, err := NewDurableForwarder(remote.URL, "test", t.TempDir(), 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	start := time.Now()
	for i := 0; i < 10; i++ {
		forwarder.Forward("tester", []json.RawMessage{json.RawMessage(`{"id":"event"}`)})
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("delivery blocked admission")
	}
	if status := forwarder.Status(); status.Pending < 1 || !status.Durable {
		t.Fatalf("event not retained: %+v", status)
	}
}
func TestAuthenticationFailureKeepsLogDeliveryRetryable(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer remote.Close()
	forwarder := NewLogForwarder(remote.URL, "wrong", nil)
	defer forwarder.Close()
	err := forwarder.Send(context.Background(), []json.RawMessage{json.RawMessage(`{"event":{"id":"one"}}`)})
	if err == nil || err == ErrPermanent {
		t.Fatalf("configuration error discards audit: %v", err)
	}
}
func TestFloodingActorIsShedNearCapacityWhileRareActorsAreKept(t *testing.T) {
	release := make(chan struct{})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer remote.Close()
	defer close(release)
	forwarder, err := NewDurableForwarder(remote.URL, "test", t.TempDir(), 40*4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	forwarder.ShedAt, forwarder.ShedPerActor = 0.5, 5
	event := json.RawMessage(`{"id":"e"}`)
	for i := 0; i < 40; i++ {
		forwarder.Forward("system:serviceaccount:ci:flooder", []json.RawMessage{event})
	}
	forwarder.Forward("m.ivanova", []json.RawMessage{event})
	status := forwarder.Status()
	if status.Shed != 15 || status.ShedActors["system:serviceaccount:ci:flooder"] != 15 {
		t.Fatalf("flood not capped: shed=%d actors=%v", status.Shed, status.ShedActors)
	}
	if status.Pending != 26 || status.Rejected != 0 {
		t.Fatalf("rare actor or admitted flood events missing: %+v", status.SpoolStatus)
	}
}
