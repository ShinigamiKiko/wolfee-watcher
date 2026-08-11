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

func addrArgs(ip string, port float64) map[string]interface{} {
	return map[string]interface{}{
		"addr": map[string]interface{}{
			"sa_family": "AF_INET",
			"sin_addr":  ip,
			"sin_port":  port,
		},
	}
}

func TestDedupKey_SeparatesDistinctPorts(t *testing.T) {
	base := func(port float64) *mapper.UIEvent {
		return &mapper.UIEvent{
			Pod: "pod-1", Syscall: "connect", Process: "scanner",
			Cmdline: "10.0.0.5", Args: addrArgs("10.0.0.5", port),
		}
	}
	seen := make(map[string]struct{})
	for _, port := range []float64{22, 80, 443, 3306, 6379} {
		key := dedupKey(base(port))
		if _, dup := seen[key]; dup {
			t.Fatalf("port scan collapsed: port %.0f produced an already-seen key %q", port, key)
		}
		seen[key] = struct{}{}
	}
}

func TestDedupKey_IdenticalEventsShareKey(t *testing.T) {
	a := &mapper.UIEvent{Pod: "pod-1", Syscall: "connect", Process: "api", Cmdline: "10.0.0.5", Args: addrArgs("10.0.0.5", 443)}
	b := &mapper.UIEvent{Pod: "pod-1", Syscall: "connect", Process: "api", Cmdline: "10.0.0.5", Args: addrArgs("10.0.0.5", 443)}
	if dedupKey(a) != dedupKey(b) {
		t.Fatalf("identical events must share a dedup key: %q vs %q", dedupKey(a), dedupKey(b))
	}
}

func TestDedupKey_SeparatesContainersInSamePod(t *testing.T) {
	a := &mapper.UIEvent{Pod: "pod-1", Container: "app", Syscall: "execve", Process: "sh", Cmdline: "/bin/sh"}
	b := &mapper.UIEvent{Pod: "pod-1", Container: "sidecar", Syscall: "execve", Process: "sh", Cmdline: "/bin/sh"}
	if dedupKey(a) == dedupKey(b) {
		t.Fatal("events from different containers must not share a dedup key")
	}
}

func TestDedupKey_SeparatesNumericOnlyArgs(t *testing.T) {
	a := &mapper.UIEvent{Pod: "pod-1", Syscall: "kill", Process: "sh", Args: map[string]interface{}{"pid": float64(101), "sig": float64(9)}}
	b := &mapper.UIEvent{Pod: "pod-1", Syscall: "kill", Process: "sh", Args: map[string]interface{}{"pid": float64(202), "sig": float64(9)}}
	if dedupKey(a) == dedupKey(b) {
		t.Fatal("events differing only in numeric args must not share a dedup key")
	}
}

func TestArgsFingerprint_StableAcrossMapOrder(t *testing.T) {
	a := map[string]interface{}{"one": "1", "two": "2", "three": float64(3)}
	b := map[string]interface{}{"three": float64(3), "two": "2", "one": "1"}
	if argsFingerprint(a) != argsFingerprint(b) {
		t.Fatal("args fingerprint must not depend on map iteration order")
	}
	if argsFingerprint(nil) != 0 {
		t.Fatal("empty args must fingerprint to 0")
	}
}

func newTestHub() *Hub {
	return &Hub{
		dedup:           make(map[string]time.Time),
		dedupTTL:        defaultDedupTTL,
		dedupMaxEntries: defaultDedupMaxEntries,
	}
}

func TestShouldDedup_ExemptsSecurityCriticalSyscalls(t *testing.T) {
	h := newTestHub()
	for _, sc := range []string{"ptrace", "bpf", "init_module", "setns", "capset", "security_inode_unlink"} {
		if h.shouldDedup(&mapper.UIEvent{Pod: "pod-1", Syscall: sc}) {
			t.Errorf("syscall %q must never be deduplicated", sc)
		}
	}
	if !h.shouldDedup(&mapper.UIEvent{Pod: "pod-1", Syscall: "openat"}) {
		t.Error("high-volume syscall openat should still be deduplicated")
	}
}

func TestShouldDedup_DisabledWithZeroTTL(t *testing.T) {
	h := newTestHub()
	h.dedupTTL = 0
	if h.shouldDedup(&mapper.UIEvent{Pod: "pod-1", Syscall: "openat"}) {
		t.Fatal("zero TTL must disable dedup entirely")
	}
}

func TestShouldDedup_SkipsEventsWithoutPod(t *testing.T) {
	h := newTestHub()
	if h.shouldDedup(&mapper.UIEvent{Syscall: "openat"}) {
		t.Fatal("events without a pod must skip dedup")
	}
}

func TestMarkSeen_SuppressesOnlyWithinTTL(t *testing.T) {
	h := newTestHub()
	if h.markSeen("k") {
		t.Fatal("first occurrence must not be reported as duplicate")
	}
	if !h.markSeen("k") {
		t.Fatal("second occurrence within TTL must be reported as duplicate")
	}
	h.dedup["k"] = time.Now().Add(-(h.dedupTTL + time.Millisecond))
	if h.markSeen("k") {
		t.Fatal("expired entry must not suppress the event")
	}
}

func TestSweepDedup_DropsExpiredEntriesBeforeFlushing(t *testing.T) {
	h := newTestHub()
	h.dedupMaxEntries = 4
	now := time.Now()
	h.dedup["fresh"] = now
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		h.dedup[k] = now.Add(-(h.dedupTTL + time.Second))
	}
	h.dedupMu.Lock()
	h.sweepDedupLocked(now)
	h.dedupMu.Unlock()
	if len(h.dedup) != 1 {
		t.Fatalf("expected only the fresh entry to survive, got %d entries", len(h.dedup))
	}
	if _, ok := h.dedup["fresh"]; !ok {
		t.Fatal("fresh entry must survive the sweep")
	}
	if h.cntDedupFlush.Load() != 0 {
		t.Fatal("sweep must not flush when expiring entries is enough")
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
	h.dedup[dedupKey(ev)] = time.Now()

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
	h.dedup[dedupKey(ev)] = time.Now()

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

func TestBroadcastDedup_ExemptSyscallIsNeverDeduped(t *testing.T) {
	h := newTestHub()
	ev := &mapper.UIEvent{Pod: "pod-1", Syscall: "ptrace", Execpath: "/usr/bin/gdb"}
	h.dedup[dedupKey(ev)] = time.Now()

	func() {
		defer func() { recover() }()
		h.Broadcast(ev)
	}()

	if h.cntDedup.Load() != 0 {
		t.Fatalf("exempt syscall must bypass dedup, cntDedup = %d", h.cntDedup.Load())
	}
}

func TestBroadcastDedup_ExpiredEntryPassesFilter(t *testing.T) {
	h := newTestHub()
	ev := &mapper.UIEvent{Pod: "pod-1", Syscall: "connect"}

	h.dedup[dedupKey(ev)] = time.Now().Add(-(h.dedupTTL + time.Millisecond))

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
