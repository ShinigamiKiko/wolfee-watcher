package hub

import (
	"testing"
	"time"

	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
)

func TestAlwaysPassContainsSecurityCriticalEvents(t *testing.T) {
	required := []string{

		"connect", "bind", "accept", "accept4", "sendto",

		"execve", "execveat", "memfd_create",

		"ptrace", "process_vm_writev",

		"bpf", "init_module", "finit_module",

		"socket",

		"io_uring_setup", "io_uring_enter", "io_uring_register",

		"sched_process_exec", "sched_process_fork", "sched_process_exit",
		"task_rename", "sched_switch",
		"module_load", "module_free",
		"cgroup_mkdir", "cgroup_rmdir", "cgroup_attach_task",

		"openat2", "kill",

		"security_file_open", "security_socket_connect", "security_bprm_check",
		"security_inode_unlink", "security_mmap_file", "security_socket_bind",
		"security_kernel_read_file",
	}
	for _, sc := range required {
		if !alwaysPass[sc] {
			t.Errorf("alwaysPass[%q] = false; critical event must not be filtered", sc)
		}
	}
}

func TestDedupKey_UsesCommandline(t *testing.T) {
	ev := &mapper.UIEvent{Pod: "pod", Syscall: "execve", Process: "bash", Cmdline: "/bin/sh -c id"}
	got := dedupKey(ev)
	want := "pod:execve:bash:/bin/sh -c id"
	if got != want {
		t.Fatalf("dedupKey = %q, want %q", got, want)
	}
}

func TestDedupKey_FallsBackToExecpath(t *testing.T) {
	ev := &mapper.UIEvent{Pod: "pod", Syscall: "execve", Process: "curl", Execpath: "/usr/bin/curl"}
	got := dedupKey(ev)
	want := "pod:execve:curl:/usr/bin/curl"
	if got != want {
		t.Fatalf("dedupKey = %q, want %q", got, want)
	}
}

func TestDedupKey_FallsBackToProcess(t *testing.T) {
	ev := &mapper.UIEvent{Pod: "pod", Syscall: "connect", Process: "nginx"}
	got := dedupKey(ev)
	want := "pod:connect:nginx"
	if got != want {
		t.Fatalf("dedupKey = %q, want %q", got, want)
	}
}

func TestDedupKey_FallsBackToSyscall(t *testing.T) {
	ev := &mapper.UIEvent{Pod: "pod", Syscall: "bind"}
	got := dedupKey(ev)
	want := "pod:bind"
	if got != want {
		t.Fatalf("dedupKey = %q, want %q", got, want)
	}
}

func TestDedupKey_FallsBackToPod(t *testing.T) {
	ev := &mapper.UIEvent{Pod: "pod-1"}
	got := dedupKey(ev)
	want := "pod-1"
	if got != want {
		t.Fatalf("dedupKey = %q, want %q", got, want)
	}
}

func newTestHub() *Hub {
	return &Hub{
		dedup: make(map[string]time.Time),
	}
}

func TestBroadcastFilter_DropsNoisySyscall(t *testing.T) {
	h := newTestHub()

	h.Broadcast(&mapper.UIEvent{Pod: "pod", Syscall: "read"})
	if h.cntReceived.Load() != 1 {
		t.Fatalf("cntReceived = %d, want 1", h.cntReceived.Load())
	}
	if h.cntDropped.Load() != 1 {
		t.Fatalf("cntDropped = %d, want 1 for noisy syscall", h.cntDropped.Load())
	}
}

func TestBroadcastFilter_DropsMultipleNoisySyscalls(t *testing.T) {
	noisy := []string{"read", "write", "poll", "epoll_wait", "futex", "nanosleep"}
	h := newTestHub()
	for _, sc := range noisy {
		h.Broadcast(&mapper.UIEvent{Pod: "pod", Syscall: sc})
	}
	if h.cntDropped.Load() != int64(len(noisy)) {
		t.Fatalf("cntDropped = %d, want %d", h.cntDropped.Load(), len(noisy))
	}
}

func TestBroadcastFilter_PassesEventWithExecpath(t *testing.T) {

	h := newTestHub()
	ev := &mapper.UIEvent{Pod: "pod-1", Syscall: "open", Execpath: "/etc/passwd"}
	key := dedupKey(ev)
	h.dedup[key] = time.Now()

	h.Broadcast(ev)
	if h.cntDropped.Load() != 0 {
		t.Fatal("event with execpath must not be counted as filtered drop")
	}
	if h.cntDedup.Load() != 1 {
		t.Fatalf("cntDedup = %d, want 1", h.cntDedup.Load())
	}
}

func TestBroadcastFilter_PassesEventWithCmdline(t *testing.T) {
	h := newTestHub()
	ev := &mapper.UIEvent{Pod: "pod-1", Syscall: "openat", Cmdline: "cat /etc/shadow"}
	key := dedupKey(ev)
	h.dedup[key] = time.Now()

	h.Broadcast(ev)
	if h.cntDropped.Load() != 0 {
		t.Fatal("event with cmdline must not be counted as filtered drop")
	}
}

func TestBroadcastDedup_SecondIdenticalEventIsDeduped(t *testing.T) {
	h := newTestHub()
	ev := &mapper.UIEvent{Pod: "pod-1", Syscall: "execve", Execpath: "/bin/sh"}

	h.dedup[dedupKey(ev)] = time.Now()

	h.Broadcast(ev)
	if h.cntDedup.Load() != 1 {
		t.Fatalf("cntDedup = %d, want 1 for duplicate event", h.cntDedup.Load())
	}
	if h.cntDropped.Load() != 0 {
		t.Fatal("deduped event must not increment cntDropped")
	}
}

func TestBroadcastDedup_ExpiredEntryPassesFilter(t *testing.T) {
	h := newTestHub()
	ev := &mapper.UIEvent{Pod: "pod-1", Syscall: "connect"}

	h.dedup[dedupKey(ev)] = time.Now().Add(-(dedupTTL + time.Millisecond))

	func() {
		defer func() { recover() }()
		h.Broadcast(ev)
	}()

	if h.cntDedup.Load() != 0 {
		t.Fatalf("expired dedup entry should not block event, cntDedup = %d", h.cntDedup.Load())
	}
}

func TestBroadcastDedup_NoPodSkipsDedup(t *testing.T) {

	h := newTestHub()
	ev := &mapper.UIEvent{Syscall: "execve", Execpath: "/bin/sh"}

	func() {
		defer func() { recover() }()
		h.Broadcast(ev)
	}()

	if h.cntDedup.Load() != 0 {
		t.Fatalf("event without pod should skip dedup, cntDedup = %d", h.cntDedup.Load())
	}
	if h.cntDropped.Load() != 0 {
		t.Fatalf("event without pod + with execpath should not be dropped, cntDropped = %d",
			h.cntDropped.Load())
	}
}

func TestEnvInt_DefaultOnMissing(t *testing.T) {
	if got := envInt("__MISSING_VAR_XYZ__", 42); got != 42 {
		t.Fatalf("envInt missing key = %d, want 42", got)
	}
}

func TestEnvBool_DefaultOnMissing(t *testing.T) {
	if got := envBool("__MISSING_VAR_XYZ__", true); !got {
		t.Fatal("envBool missing key should return default true")
	}
}
