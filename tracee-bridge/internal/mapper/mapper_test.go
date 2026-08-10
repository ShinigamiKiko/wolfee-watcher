package mapper

import (
	"testing"

	"github.com/wolfee-watcher/tracee-bridge/internal/events"
)

func TestMapClassifiesEventKinds(t *testing.T) {
	for _, tt := range []struct {
		name string
		want events.Kind
	}{
		{"io_uring_enter", events.Syscall},
		{"security_file_open", events.LSMHook},
		{"module_load", events.Tracepoint},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ev := Map(&TraceeEvent{EventName: tt.name, PodName: "pod", PodNamespace: "default"})
			if ev == nil || ev.EventKind != tt.want {
				t.Fatalf("event kind = %q, want %q", ev.EventKind, tt.want)
			}
		})
	}
}
