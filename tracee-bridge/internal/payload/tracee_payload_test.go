package payload

import (
	"strings"
	"testing"
)

func TestParseTraceePayloadStream_Array(t *testing.T) {
	raw := `[{"timestamp":1,"eventName":"execve"},{"timestamp":2,"eventName":"connect"}]`
	evs, err := ParseTraceePayloadStream(strings.NewReader(raw), 1<<20)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("expected 2 events, got %d", len(evs))
	}
	if evs[0].EventName != "execve" || evs[1].EventName != "connect" {
		t.Fatalf("unexpected event names: %+v %+v", evs[0].EventName, evs[1].EventName)
	}
}

func TestParseTraceePayloadStream_Object(t *testing.T) {
	raw := `{"timestamp":1,"eventName":"openat"}`
	evs, err := ParseTraceePayloadStream(strings.NewReader(raw), 1<<20)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].EventName != "openat" {
		t.Fatalf("unexpected event name: %s", evs[0].EventName)
	}
}

func TestParseTraceePayloadStream_Invalid(t *testing.T) {
	raw := `"not-json-object-or-array"`
	_, err := ParseTraceePayloadStream(strings.NewReader(raw), 1<<20)
	if err == nil {
		t.Fatal("expected error for invalid payload")
	}
}
