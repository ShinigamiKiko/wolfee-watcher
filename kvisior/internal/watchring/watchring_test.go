package watchring

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/events"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

func TestRingSeparatesPodsWithSameName(t *testing.T) {
	ring := New(context.Background())
	now := time.Now()
	ring.Add("default", "worker", "uid-old", events.Syscall, "execve", json.RawMessage(`{"podUID":"uid-old"}`), now)
	ring.Add("default", "worker", "uid-new", events.Syscall, "execve", json.RawMessage(`{"podUID":"uid-new"}`), now)

	selection := store.PodWatchSelection{Syscalls: []string{"execve"}}
	old := ring.Get("default", "worker", "uid-old", "", selection)
	newPod := ring.Get("default", "worker", "uid-new", "", selection)
	if len(old) != 1 || len(newPod) != 1 {
		t.Fatalf("same-name pods were not isolated: old=%d new=%d", len(old), len(newPod))
	}
}

func TestRingSeparatesEventKinds(t *testing.T) {
	ring := New(context.Background())
	now := time.Now()
	ring.Add("default", "worker", "uid", events.Syscall, "open", json.RawMessage(`{"event_kind":"syscall"}`), now)
	ring.Add("default", "worker", "uid", events.LSMHook, "security_file_open", json.RawMessage(`{"event_kind":"lsm_hook"}`), now)

	if got := ring.Get("default", "worker", "uid", "", store.PodWatchSelection{Syscalls: []string{"open"}}); len(got) != 1 {
		t.Fatalf("syscall selection returned %d events", len(got))
	}
	if got := ring.Get("default", "worker", "uid", "", store.PodWatchSelection{LSMHooks: []string{"security_file_open"}}); len(got) != 1 {
		t.Fatalf("LSM selection returned %d events", len(got))
	}
}

func TestRingUsesContainerFallbackWhenUIDIsMissing(t *testing.T) {
	ring := New(context.Background())
	now := time.Now()
	ring.Add("default", "worker", "", events.Syscall, "io_uring_setup",
		json.RawMessage(`{"containerId":"container-current","event_kind":"syscall"}`), now)

	selection := store.PodWatchSelection{Syscalls: []string{"io_uring_setup"}}
	if got := ring.Get("default", "worker", "uid-current", "container-current", selection); len(got) != 1 {
		t.Fatalf("container fallback returned %d events, want 1", len(got))
	}
	if got := ring.Get("default", "worker", "uid-current", "container-other", selection); len(got) != 0 {
		t.Fatalf("container fallback crossed identity boundary: got %d events", len(got))
	}
}
