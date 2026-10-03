package logtail

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wolfee-watcher/sentry-audit/internal/webhook"
)

func line(verb, user, resource, ns, name, sub string, code int, annotations string) string {
	return fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"a-%s-%s","stage":"ResponseComplete",`+
		`"requestURI":"/x","verb":%q,"user":{"username":%q,"groups":["g"]},"sourceIPs":["10.20.14.36"],"userAgent":"kubectl/v1.30.4",`+
		`"objectRef":{"resource":%q,"namespace":%q,"name":%q,"subresource":%q},"responseStatus":{"code":%d},`+
		`"requestReceivedTimestamp":"2026-10-01T10:00:00.000000Z","annotations":{%s}}`,
		verb, name, verb, user, resource, ns, name, sub, code, annotations)
}

func TestParseEnrichesAdmissionEvents(t *testing.T) {
	f := DefaultFilter()
	rec, ok := f.Parse([]byte(line("create", "system:serviceaccount:kube-system:deployment-controller", "pods", "prod", "p1", "", 201,
		`"policyeval.wolfee-watcher.io/event-id":"uid-1"`)))
	if !ok {
		t.Fatal("a record carrying our event id must be kept even for a system user")
	}
	if rec.EventUID != "uid-1" || rec.Event.SourceIPs[0] != "10.20.14.36" || rec.Event.UserAgent != "kubectl/v1.30.4" {
		t.Errorf("unexpected enrichment record: %+v", rec)
	}
	if !rec.Event.Allowed || rec.Event.StatusCode != 201 {
		t.Errorf("verdict not carried: %+v", rec.Event)
	}
}

func TestParseFilters(t *testing.T) {
	f := DefaultFilter()
	cases := []struct {
		name string
		line string
		keep bool
		kind webhook.EventKind
	}{
		{"person reads pods", line("list", "a.sokolov", "pods", "prod", "", "", 200, ""), true, webhook.EventKindList},
		{"controller reads pods", line("list", "system:serviceaccount:argocd:ctl", "pods", "prod", "", "", 200, ""), false, ""},
		{"service account reads secrets", line("get", "system:serviceaccount:ci:deployer", "secrets", "prod", "db", "", 200, ""), true, webhook.EventKindGet},
		{"kubelet reads secrets", line("get", "system:node:w1", "secrets", "prod", "db", "", 200, ""), false, ""},
		{"lease noise", line("update", "a.sokolov", "leases", "kube-node-lease", "w1", "", 200, ""), false, ""},
		{"kube-system controller write", line("update", "system:serviceaccount:kube-system:x", "configmaps", "kube-system", "c", "", 200, ""), false, ""},
		{"person writes in kube-system", line("patch", "m.ivanova", "configmaps", "kube-system", "coredns", "", 200, ""), true, webhook.EventKindUpdate},
		{"status subresource", line("update", "m.ivanova", "deployments", "prod", "api", "status", 200, ""), false, ""},
		{"watch", line("watch", "a.sokolov", "pods", "prod", "", "", 200, ""), false, ""},
		{"exec over websocket", line("get", "a.sokolov", "pods", "prod", "p1", "exec", 101, ""), true, webhook.EventKindExec},
		{"pod logs", line("get", "a.sokolov", "pods", "prod", "p1", "log", 200, ""), true, webhook.EventKindGet},
	}
	for _, c := range cases {
		rec, ok := f.Parse([]byte(c.line))
		if ok != c.keep {
			t.Errorf("%s: keep = %v, want %v", c.name, ok, c.keep)
			continue
		}
		if ok && rec.Event.Kind != c.kind {
			t.Errorf("%s: kind = %q, want %q", c.name, rec.Event.Kind, c.kind)
		}
	}
	rec, _ := f.Parse([]byte(line("get", "a.sokolov", "pods", "prod", "p1", "log", 200, "")))
	if rec.Event.Resource != "pods/log" {
		t.Errorf("subresource not reflected in resource: %q", rec.Event.Resource)
	}
	denied, _ := f.Parse([]byte(line("create", "d.orlov", "pods", "kube-system", "debug", "", 403, "")))
	if denied.Event.Allowed {
		t.Error("a 403 response must be recorded as denied")
	}
	if _, ok := f.Parse([]byte(`{"stage":"RequestReceived","verb":"create"}`)); ok {
		t.Error("only ResponseComplete records are kept")
	}
	if _, ok := f.Parse([]byte(`not json`)); ok {
		t.Error("garbage lines are skipped")
	}
}

type collector struct {
	mu   sync.Mutex
	recs []Record
}

func (c *collector) sink(r []Record) {
	c.mu.Lock()
	c.recs = append(c.recs, r...)
	c.mu.Unlock()
}

func (c *collector) names() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.recs))
	for _, r := range c.recs {
		out = append(out, r.Event.Name)
	}
	return strings.Join(out, ",")
}

func waitFor(t *testing.T, c *collector, want string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if c.names() == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("records = %q, want %q", c.names(), want)
}

func appendLine(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func TestTailFollowsAppendsRotationAndCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	person := func(name string) string {
		return line("create", "a.sokolov", "configmaps", "prod", name, "", 201, "") + "\n"
	}

	appendLine(t, path, person("old"))

	c := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { New(path, dir, DefaultFilter(), c.sink).Run(ctx); close(done) }()

	time.Sleep(300 * time.Millisecond)
	appendLine(t, path, person("one"))
	half := person("two")
	appendLine(t, path, half[:40])
	waitFor(t, c, "one")
	appendLine(t, path, half[40:])
	waitFor(t, c, "one,two")

	if err := os.Rename(path, filepath.Join(dir, "audit-rotated.log")); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, person("three"))
	waitFor(t, c, "one,two,three")

	cancel()
	<-done
	appendLine(t, path, person("four"))

	c2 := &collector{}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go New(path, dir, DefaultFilter(), c2.sink).Run(ctx2)
	waitFor(t, c2, "four")
}
