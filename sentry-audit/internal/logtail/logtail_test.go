package logtail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

func TestParseKeepsTheRealUserUnderImpersonation(t *testing.T) {
	f := DefaultFilter()
	raw := strings.Replace(line("delete", "m.ivanova", "secrets", "prod", "db", "", 200, `"policyeval.wolfee-watcher.io/event-id":"uid-2"`),
		`"sourceIPs"`, `"impersonatedUser":{"username":"system:serviceaccount:ci:deployer","groups":["system:masters"]},"sourceIPs"`, 1)
	rec, ok := f.Parse([]byte(raw))
	if !ok {
		t.Fatal("record dropped")
	}
	ev := rec.Event
	if ev.User != "m.ivanova" || ev.ImpersonatedUser != "system:serviceaccount:ci:deployer" ||
		len(ev.ImpersonatedGroups) != 1 || ev.ImpersonatedGroups[0] != "system:masters" {
		t.Errorf("impersonation not carried: %+v", ev)
	}
	plain, _ := f.Parse([]byte(line("delete", "m.ivanova", "secrets", "prod", "db", "", 200, "")))
	if plain.Event.ImpersonatedUser != "" {
		t.Errorf("a direct request was marked as impersonated: %+v", plain.Event)
	}
}

func TestParseKeepsEveryWebhookConfigurationChange(t *testing.T) {
	f := DefaultFilter()
	controller := "system:serviceaccount:kube-system:helm-controller"
	if _, ok := f.Parse([]byte(line("patch", controller, "validatingwebhookconfigurations", "", "kyverno", "", 200, ""))); !ok {
		t.Error("a webhook configuration change by a system account must be kept: it names who changed it")
	}
	if _, ok := f.Parse([]byte(line("list", controller, "validatingwebhookconfigurations", "", "", "", 200, ""))); ok {
		t.Error("reads by system accounts stay filtered")
	}
	if _, ok := f.Parse([]byte(line("patch", controller, "configmaps", "kube-system", "c", "", 200, ""))); ok {
		t.Error("other writes by kube-system accounts stay filtered")
	}
}

func TestParseIdentifiesWebhookConfigurationChanges(t *testing.T) {
	f := DefaultFilter()
	record := func(verb string, code int, annotations, extra string) webhook.AuditEvent {
		t.Helper()
		raw := strings.Replace(line(verb, "m.ivanova", "validatingwebhookconfigurations", "", "kyverno", "", code, annotations),
			`"sourceIPs"`, extra+`"sourceIPs"`, 1)
		rec, ok := f.Parse([]byte(raw))
		if !ok {
			t.Fatalf("%s dropped", verb)
		}
		return rec.Event
	}
	policy := `"webhook-changes.wolfee-watcher.io/object-uid":"uid-1","webhook-changes.wolfee-watcher.io/previous-resource-version":"41"`
	if ev := record("patch", 200, policy, ""); ev.UID != "uid-1" || ev.PrevResourceVersion != "41" || ev.ResourceVersion != "" {
		t.Errorf("policy annotations not read: %+v", ev)
	}
	if ev := record("create", 201, `"webhook-changes.wolfee-watcher.io/object-uid":"uid-1","webhook-changes.wolfee-watcher.io/previous-resource-version":""`, ""); ev.UID != "uid-1" || ev.PrevResourceVersion != "" {
		t.Errorf("create: %+v", ev)
	}
	empty := record("patch", 200, policy+`,"webhook-changes.wolfee-watcher.io/changed":"false"`, `"stageTimestamp":"2026-10-01T10:00:00.250000Z",`)
	if !empty.Unchanged || empty.CompletedAt == nil || empty.CompletedAt.Sub(empty.Timestamp) != 250*time.Millisecond {
		t.Errorf("a request that changed nothing must be marked, with its completion time: %+v", empty)
	}
	if ev := record("patch", 200, policy+`,"webhook-changes.wolfee-watcher.io/changed":"true"`, ""); ev.Unchanged {
		t.Errorf("a real change marked as unchanged: %+v", ev)
	}
	same := `"responseObject":{"metadata":{"name":"kyverno","uid":"uid-1","resourceVersion":"41"}},`
	if ev := record("patch", 200, policy, same); !ev.Unchanged {
		t.Errorf("a response with the revision it started from changed nothing: %+v", ev)
	}
	full := `"responseObject":{"metadata":{"name":"kyverno","uid":"uid-2","resourceVersion":"42"}},`
	if ev := record("patch", 200, "", full); ev.UID != "uid-2" || ev.ResourceVersion != "42" {
		t.Errorf("response object not read: %+v", ev)
	}
	put := strings.Replace(line("update", "m.ivanova", "validatingwebhookconfigurations", "", "kyverno", "", 200, ""),
		`"subresource":""`, `"subresource":"","uid":"uid-3","resourceVersion":"41"`, 1)
	rec, ok := f.Parse([]byte(put))
	if !ok || rec.Event.UID != "uid-3" || rec.Event.PrevResourceVersion != "41" {
		t.Errorf("a full update carries the revision it replaced: %+v", rec.Event)
	}
	gone := strings.Replace(line("delete", "m.ivanova", "validatingwebhookconfigurations", "", "kyverno", "", 200, ""),
		`"responseStatus":{"code":200}`, `"responseStatus":{"code":200,"details":{"name":"kyverno","uid":"uid-4"}}`, 1)
	rec, ok = f.Parse([]byte(gone))
	if !ok || rec.Event.UID != "uid-4" || rec.Event.PrevResourceVersion != "" {
		t.Errorf("a delete names the removed object: %+v", rec.Event)
	}
	rehearsed := strings.Replace(line("patch", "m.ivanova", "validatingwebhookconfigurations", "", "kyverno", "", 200, policy),
		`"requestURI":"/x"`, `"requestURI":"/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/kyverno?dryRun=All&fieldManager=kubectl"`, 1)
	rec, ok = f.Parse([]byte(rehearsed))
	if !ok || !rec.Event.DryRun || !rec.Event.Unchanged {
		t.Errorf("a dry-run request changes nothing and must say so: %+v", rec.Event)
	}
	trial := strings.Replace(line("delete", "m.ivanova", "validatingwebhookconfigurations", "", "kyverno", "", 200, ""),
		`"sourceIPs"`, `"requestObject":{"kind":"DeleteOptions","apiVersion":"v1","dryRun":["All"]},"sourceIPs"`, 1)
	rec, ok = f.Parse([]byte(trial))
	if !ok || !rec.Event.DryRun || !rec.Event.Unchanged {
		t.Errorf("a dry-run delete carries the option in its body: %+v", rec.Event)
	}
	labelled := strings.Replace(line("patch", "m.ivanova", "validatingwebhookconfigurations", "", "kyverno", "", 200, ""),
		`"sourceIPs"`, `"requestObject":{"metadata":{"labels":{"a":"1"}},"dryRun":["All"]},"sourceIPs"`, 1)
	rec, ok = f.Parse([]byte(labelled))
	if !ok || rec.Event.DryRun {
		t.Errorf("only delete options are read from a request body: %+v", rec.Event)
	}
	listed := strings.Replace(line("patch", "m.ivanova", "validatingwebhookconfigurations", "", "kyverno", "", 200, policy),
		`"sourceIPs"`, `"requestObject":[{"op":"add","path":"/metadata/labels/a","value":"1"}],"sourceIPs"`, 1)
	rec, ok = f.Parse([]byte(listed))
	if !ok || rec.Event.UID != "uid-1" || rec.Event.DryRun {
		t.Errorf("a JSON patch body is a list and must not break the record: ok=%v %+v", ok, rec.Event)
	}
	forged := strings.Replace(line("create", "m.ivanova", "validatingwebhookconfigurations", "", "kyverno", "", 201, ""),
		`"subresource":""`, `"subresource":"","uid":"uid-of-another-object","resourceVersion":"41"`, 1)
	rec, ok = f.Parse([]byte(forged))
	if !ok || rec.Event.UID != "" || rec.Event.PrevResourceVersion != "" {
		t.Errorf("identifiers a client put into a create request must not be taken: %+v", rec.Event)
	}
	unconditional := strings.Replace(line("update", "m.ivanova", "validatingwebhookconfigurations", "", "kyverno", "", 200, ""),
		`"subresource":""`, `"subresource":"","resourceVersion":"0"`, 1)
	rec, ok = f.Parse([]byte(unconditional))
	if !ok || rec.Event.PrevResourceVersion != "" {
		t.Errorf("revision 0 is an unconditional update, not a revision: %+v", rec.Event)
	}
	other, _ := f.Parse([]byte(strings.Replace(line("update", "m.ivanova", "configmaps", "prod", "c", "", 200, ""),
		`"subresource":""`, `"subresource":"","uid":"uid-5","resourceVersion":"7"`, 1)))
	if other.Event.UID != "" || other.Event.PrevResourceVersion != "" {
		t.Errorf("only watched resources are identified: %+v", other.Event)
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

func (c *collector) sink(_ context.Context, r []Record) error {
	c.mu.Lock()
	c.recs = append(c.recs, r...)
	c.mu.Unlock()
	return nil
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
	done2 := make(chan struct{})
	defer func() { cancel2(); <-done2 }()
	go func() { defer close(done2); New(path, dir, DefaultFilter(), c2.sink).Run(ctx2) }()
	waitFor(t, c2, "four")
}

func TestStatusReportsBacklogAndRotationHeadroom(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	person := func(name string) string {
		return line("create", "a.sokolov", "configmaps", "prod", name, "", 201, "") + "\n"
	}
	appendLine(t, path, person("before"))
	var offline atomic.Bool
	c := &collector{}
	tailer := New(path, dir, DefaultFilter(), func(ctx context.Context, r []Record) error {
		if offline.Load() {
			return errors.New("receiver offline")
		}
		return c.sink(ctx, r)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() { defer close(done); tailer.Run(ctx) }()
	status := func(ok func(Status) bool) Status {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			s := tailer.Status()
			if ok(s) {
				return s
			}
			if time.Now().After(deadline) {
				t.Fatalf("status = %+v", s)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	status(func(s Status) bool { return s.State == StateReading })
	offline.Store(true)
	one, two := person("one"), person("two")
	appendLine(t, path, one+two)
	s := status(func(s Status) bool { return s.State == StateFailing && s.BacklogBytes > 0 })
	if s.BacklogFiles != 1 || s.Headroom != nil || s.BacklogBytes != int64(len(one+two)) {
		t.Fatalf("live backlog = %+v", s)
	}
	if err := os.Rename(path, filepath.Join(dir, "audit-1.log")); err != nil {
		t.Fatal(err)
	}
	three := person("three")
	appendLine(t, path, three)
	s = status(func(s Status) bool { return s.Headroom != nil })
	if *s.Headroom != 1 || s.BacklogFiles != 2 || s.BacklogBytes != int64(len(one+two+three)) {
		t.Fatalf("rotated backlog = %+v", s)
	}
	offline.Store(false)
	waitFor(t, c, "one,two,three")
	s = status(func(s Status) bool { return s.BacklogBytes == 0 && s.Headroom == nil })
	if s.BacklogFiles != 0 || s.LagSeconds != 0 {
		t.Fatalf("drained backlog = %+v", s)
	}
}

func TestTailDeliversAsSoonAsTheReceiverIsBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendLine(t, path, "")
	var down atomic.Bool
	down.Store(true)
	var failures atomic.Int32
	c := &collector{}
	tailer := New(path, dir, DefaultFilter(), func(ctx context.Context, r []Record) error {
		if down.Load() {
			failures.Add(1)
			return errors.New("offline")
		}
		return c.sink(ctx, r)
	})
	tailer.Probe = func(context.Context) error {
		if down.Load() {
			return errors.New("offline")
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() { defer close(done); tailer.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)
	appendLine(t, path, line("create", "a.sokolov", "configmaps", "prod", "late", "", 201, "")+"\n")
	deadline := time.Now().Add(20 * time.Second)
	for failures.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if failures.Load() < 4 {
		t.Fatalf("only %d attempts", failures.Load())
	}
	restored := time.Now()
	down.Store(false)
	for c.names() != "late" {
		if time.Since(restored) > probeInterval+2*pollInterval {
			t.Fatalf("not delivered %s after the receiver came back", time.Since(restored))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
