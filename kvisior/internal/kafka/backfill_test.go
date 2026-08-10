package kafka

import (
	"testing"

	"github.com/wolfee-watcher/kvisior/internal/events"
)

func TestCaptureForForensicsUsesEventKind(t *testing.T) {
	tests := []struct {
		name  string
		kind  events.Kind
		event string
		want  bool
	}{
		{"io_uring syscall", events.Syscall, "io_uring_enter", true},
		{"LSM hook", events.LSMHook, "security_file_open", true},
		{"tracepoint", events.Tracepoint, "module_load", true},
		{"wrong kind does not capture LSM", events.Tracepoint, "security_file_open", false},
		{"ordinary syscall", events.Syscall, "read", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := captureForForensics(tt.kind, tt.event); got != tt.want {
				t.Fatalf("captureForForensics(%q, %q) = %v, want %v", tt.kind, tt.event, got, tt.want)
			}
		})
	}
}
