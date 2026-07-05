package consumer

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/wolfee-watcher/anomaly-detector/internal/enricher"
	"github.com/wolfee-watcher/anomaly-detector/internal/recon"
)

func testConsumer() *Consumer {
	return &Consumer{
		enrich:    enricher.New(fake.NewSimpleClientset()),
		recon:     recon.New(),
		memfdSeen: make(map[string]memfdState),
		dedupSeen: make(map[string]time.Time),
	}
}

func event(fields map[string]interface{}) []byte {
	b, _ := json.Marshal(fields)
	return b
}

func TestEvaluateRaw_IgnoresEmptyNamespace(t *testing.T) {
	c := testConsumer()
	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"pod": "pod-1", "syscall": "execve",
	}))
	if len(got) != 0 {
		t.Fatalf("expected nil for empty namespace, got %v", got)
	}
}

func TestEvaluateRaw_IgnoresEmptyPod(t *testing.T) {
	c := testConsumer()
	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"namespace": "prod", "syscall": "execve",
	}))
	if len(got) != 0 {
		t.Fatalf("expected nil for empty pod, got %v", got)
	}
}

func TestEvaluateRaw_IgnoresSystemNamespace(t *testing.T) {
	for _, ns := range []string{"kube-system", "kube-public", "wolfee-watcher", "cert-manager"} {
		c := testConsumer()
		got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
			"namespace": ns, "pod": "pod-1", "syscall": "ptrace",
		}))
		if len(got) != 0 {
			t.Fatalf("namespace %q should be ignored, got %v", ns, got)
		}
	}
}

func TestEvaluateRaw_Ptrace(t *testing.T) {
	c := testConsumer()
	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"namespace": "prod", "pod": "attacker", "syscall": "ptrace",
	}))
	if len(got) != 1 || got[0].Kind != KindProcessInjection {
		t.Fatalf("want [KindProcessInjection], got %v", got)
	}
}

func TestEvaluateRaw_Capset_RuntimeInitSuppressed(t *testing.T) {
	for _, proc := range []string{"runc:[2:INIT]", "runc", "runc init", "crun", "containerd-shim-runc-v2"} {
		c := testConsumer()
		got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
			"namespace": "stress-test", "pod": "wget-tester-x", "syscall": "capset",
			"process": proc,
		}))
		if len(got) != 0 {
			t.Fatalf("capset from runtime init %q must not alert, got %v", proc, got)
		}
	}
}

func TestEvaluateRaw_Capset_WorkloadProcessAlerts(t *testing.T) {
	c := testConsumer()
	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"namespace": "prod", "pod": "app-1", "syscall": "capset",
		"process": "python",
	}))
	if len(got) != 1 || got[0].Kind != KindPrivEscalation {
		t.Fatalf("capset from workload process must alert, got %v", got)
	}
}

func TestEvaluateRaw_InitModule(t *testing.T) {
	for _, sc := range []string{"init_module", "finit_module"} {
		c := testConsumer()
		got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
			"namespace": "prod", "pod": "pod-1", "syscall": sc,
		}))
		if len(got) != 1 || got[0].Kind != KindKernelModuleLoad {
			t.Fatalf("syscall %q: want [KindKernelModuleLoad], got %v", sc, got)
		}
	}
}

func TestEvaluateRaw_BPF(t *testing.T) {
	c := testConsumer()
	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "bpf",
	}))
	if len(got) != 1 || got[0].Kind != KindEBPFLoad {
		t.Fatalf("want [KindEBPFLoad], got %v", got)
	}
}

func TestEvaluateRaw_IOUring(t *testing.T) {
	for _, sc := range []string{"io_uring_setup", "io_uring_enter", "io_uring_register"} {
		c := testConsumer()
		got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
			"namespace": "prod", "pod": "attacker", "syscall": sc,
		}))
		if len(got) != 1 || got[0].Kind != KindIOUring {
			t.Fatalf("syscall %q: want [KindIOUring], got %v", sc, got)
		}
		if got[0].Syscall != sc {
			t.Fatalf("syscall %q: want Syscall=%q, got %q", sc, sc, got[0].Syscall)
		}
	}
}

func TestEvaluateRaw_RawSocket_StringDomain(t *testing.T) {
	c := testConsumer()
	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "socket",
		"args": map[string]interface{}{
			"domain": "AF_INET",
			"type":   "SOCK_RAW",
		},
	}))
	if len(got) != 1 || got[0].Kind != KindRawSocket {
		t.Fatalf("want [KindRawSocket], got %v", got)
	}
}

func TestEvaluateRaw_RawSocket_NumericDomain(t *testing.T) {
	c := testConsumer()

	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "socket",
		"args": map[string]interface{}{
			"domain": float64(2),
			"type":   float64(3),
		},
	}))
	if len(got) != 1 || got[0].Kind != KindRawSocket {
		t.Fatalf("want [KindRawSocket] for numeric domain/type, got %v", got)
	}
}

func TestEvaluateRaw_RawSocket_AFPacket(t *testing.T) {
	c := testConsumer()

	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "socket",
		"args": map[string]interface{}{
			"domain": float64(17),
			"type":   float64(3),
		},
	}))
	if len(got) != 1 || got[0].Kind != KindRawSocket {
		t.Fatalf("want [KindRawSocket] for AF_PACKET, got %v", got)
	}
}

func TestEvaluateRaw_NormalSocket_NoAnomaly(t *testing.T) {
	c := testConsumer()

	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "socket",
		"args": map[string]interface{}{
			"domain": "AF_INET",
			"type":   "SOCK_STREAM",
		},
	}))
	if len(got) != 0 {
		t.Fatalf("TCP socket should not generate anomaly, got %v", got)
	}
}

func TestEvaluateRaw_SuspiciousBind_Metasploit(t *testing.T) {
	c := testConsumer()
	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "bind",
		"args": map[string]interface{}{
			"addr": map[string]interface{}{
				"sa_family": "AF_INET",
				"sin_port":  float64(4444),
			},
		},
	}))
	if len(got) != 1 || got[0].Kind != KindSuspiciousBind {
		t.Fatalf("want [KindSuspiciousBind] for port 4444, got %v", got)
	}
	if got[0].DstPort != 4444 {
		t.Fatalf("want DstPort=4444, got %d", got[0].DstPort)
	}
}

func TestEvaluateRaw_SuspiciousBind_C2Ports(t *testing.T) {
	suspiciousPorts := []uint32{1337, 31337, 9001, 6666, 6667}
	for _, port := range suspiciousPorts {
		c := testConsumer()
		got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
			"namespace": "prod", "pod": "pod-1", "syscall": "bind",
			"args": map[string]interface{}{
				"addr": map[string]interface{}{
					"sa_family": "AF_INET",
					"sin_port":  float64(port),
				},
			},
		}))
		if len(got) != 1 || got[0].Kind != KindSuspiciousBind {
			t.Errorf("port %d: want [KindSuspiciousBind], got %v", port, got)
		}
	}
}

func TestEvaluateRaw_NormalBind_NoAnomaly(t *testing.T) {
	c := testConsumer()
	got := c.evaluateRaw(context.Background(), event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "bind",
		"args": map[string]interface{}{
			"addr": map[string]interface{}{
				"sa_family": "AF_INET",
				"sin_port":  float64(8080),
			},
		},
	}))
	if len(got) != 0 {
		t.Fatalf("port 8080 bind should not generate anomaly, got %v", got)
	}
}

func TestFilelessExec_Detected(t *testing.T) {
	c := testConsumer()
	ctx := context.Background()

	memfd := event(map[string]interface{}{
		"namespace": "prod", "pod": "compromised", "syscall": "memfd_create", "pid": "777",
	})
	execve := event(map[string]interface{}{
		"namespace": "prod", "pod": "compromised", "syscall": "execve", "pid": "777",
	})

	if got := c.evaluateRaw(ctx, memfd); len(got) != 0 {
		t.Fatalf("memfd_create should return nil (pending), got %v", got)
	}

	got := c.evaluateRaw(ctx, execve)
	if len(got) != 1 || got[0].Kind != KindFilelessExec {
		t.Fatalf("want [KindFilelessExec], got %v", got)
	}
}

func TestFilelessExec_StateConsumedOnDetection(t *testing.T) {

	c := testConsumer()
	ctx := context.Background()

	memfd := event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "memfd_create", "pid": "100",
	})
	execve := event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "execve", "pid": "100",
	})

	c.evaluateRaw(ctx, memfd)
	if got := c.evaluateRaw(ctx, execve); len(got) != 1 {
		t.Fatalf("first execve: want 1 anomaly, got %v", got)
	}

	if got := c.evaluateRaw(ctx, execve); len(got) != 0 {
		t.Fatalf("second execve: memfd state should be consumed, got %v", got)
	}
}

func TestFilelessExec_ExpiredWindow(t *testing.T) {
	c := testConsumer()
	ctx := context.Background()
	ns, pod, pid := "prod", "pod-1", "42"

	key := ns + "/" + pod + "/" + pid
	c.memfdMu.Lock()
	c.memfdSeen[key] = memfdState{ts: time.Now().Add(-(filelessWindow + time.Second)), pid: pid}
	c.memfdMu.Unlock()

	execve := event(map[string]interface{}{
		"namespace": ns, "pod": pod, "syscall": "execve", "pid": pid,
	})
	got := c.evaluateRaw(ctx, execve)
	if len(got) != 0 {
		t.Fatalf("expired window: want nil, got %v", got)
	}
}

func TestFilelessExec_DifferentPid_NotDetected(t *testing.T) {
	c := testConsumer()
	ctx := context.Background()

	memfd := event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "memfd_create", "pid": "111",
	})
	execve := event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-1", "syscall": "execve", "pid": "222",
	})

	c.evaluateRaw(ctx, memfd)
	got := c.evaluateRaw(ctx, execve)
	if len(got) != 0 {
		t.Fatalf("different pid: want nil, got %v", got)
	}
}

func TestFilelessExec_DifferentPod_NotDetected(t *testing.T) {
	c := testConsumer()
	ctx := context.Background()

	memfd := event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-A", "syscall": "memfd_create", "pid": "1",
	})
	execve := event(map[string]interface{}{
		"namespace": "prod", "pod": "pod-B", "syscall": "execve", "pid": "1",
	})

	c.evaluateRaw(ctx, memfd)
	got := c.evaluateRaw(ctx, execve)
	if len(got) != 0 {
		t.Fatalf("different pod: want nil, got %v", got)
	}
}

func TestEvalSendto_EmitsBothSuspiciousAndPortScan(t *testing.T) {
	c := testConsumer()
	ctx := context.Background()
	sendto := func(port int) []byte {
		return event(map[string]interface{}{
			"namespace": "prod", "pod": "scanner", "syscall": "sendto",
			"args": map[string]interface{}{
				"addr": map[string]interface{}{
					"sa_family": "AF_INET",
					"sin_addr":  "203.0.113.50",
					"sin_port":  float64(port),
				},
			},
		})
	}
	for _, p := range []int{80, 81, 82, 83} {
		c.evaluateRaw(ctx, sendto(p))
	}
	got := c.evaluateRaw(ctx, sendto(22))

	kinds := map[AnomalyKind]bool{}
	for _, a := range got {
		kinds[a.Kind] = true
	}
	if !kinds[KindSuspiciousPort] || !kinds[KindPortScan] {
		t.Fatalf("want both suspicious_port and port_scan, got %d event(s): %+v", len(got), got)
	}
}
