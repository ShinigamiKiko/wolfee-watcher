package watchring

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestRingSeparatesPodsWithSameName(t *testing.T) {
	ring := New(context.Background())
	now := time.Now()
	ring.Add("default", "worker", "uid-old", "execve", json.RawMessage(`{"podUID":"uid-old"}`), now)
	ring.Add("default", "worker", "uid-new", "execve", json.RawMessage(`{"podUID":"uid-new"}`), now)

	old := ring.Get("default", "worker", "uid-old", []string{"execve"})
	newPod := ring.Get("default", "worker", "uid-new", []string{"execve"})
	if len(old) != 1 || len(newPod) != 1 {
		t.Fatalf("same-name pods were not isolated: old=%d new=%d", len(old), len(newPod))
	}
}
