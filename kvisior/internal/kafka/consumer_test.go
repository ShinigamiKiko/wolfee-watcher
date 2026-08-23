package kafka

import "testing"

func TestShouldPersistRuntimeEvent(t *testing.T) {
	tests := []struct {
		name    string
		syscall string
		watched bool
		want    bool
	}{
		{name: "execve is always persisted", syscall: "execve", want: true},
		{name: "execveat is always persisted", syscall: "execveat", want: true},
		{name: "selected watch event is persisted", syscall: "security_file_open", watched: true, want: true},
		{name: "unselected event is not persisted", syscall: "security_file_open", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldPersistRuntimeEvent(tt.syscall, tt.watched); got != tt.want {
				t.Fatalf("shouldPersistRuntimeEvent(%q, %v) = %v, want %v", tt.syscall, tt.watched, got, tt.want)
			}
		})
	}
}
