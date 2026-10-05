package logtail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wolfee-watcher/sentry-audit/internal/webhook"
)

func step(t *testing.T, tail *Tailer) error {
	t.Helper()
	err := tail.drain(context.Background())
	for err == nil && tail.rotated() {
		if err = tail.drain(context.Background()); err != nil {
			break
		}
		if openErr := tail.open(false); openErr != nil {
			t.Fatal(openErr)
		}
		err = tail.drain(context.Background())
	}
	return err
}

func record(name string) string {
	return line("create", "alice", "configmaps", "prod", name, "", 201, "") + "\n"
}

func TestParseConnectStageAndFailedRequests(t *testing.T) {
	f := DefaultFilter()
	started := strings.Replace(line("get", "a.sokolov", "pods", "prod", "p1", "exec", 101,
		`"k8sevents.wolfee-watcher.io/event-id":"uid-9"`), `"stage":"ResponseComplete"`, `"stage":"ResponseStarted"`, 1)
	rec, ok := f.Parse([]byte(started))
	if !ok || rec.EventUID != "uid-9" || rec.Event.Kind != webhook.EventKindExec || !rec.Event.Allowed {
		t.Fatalf("an exec session must be reported when it starts: ok=%v rec=%+v", ok, rec)
	}
	listStarted := strings.Replace(line("list", "a.sokolov", "pods", "prod", "", "", 200, ""),
		`"stage":"ResponseComplete"`, `"stage":"ResponseStarted"`, 1)
	if _, ok := f.Parse([]byte(listStarted)); ok {
		t.Error("ResponseStarted is taken only for exec, attach and port-forward")
	}
	for _, code := range []int{404, 409, 422, 500} {
		if _, ok := f.Parse([]byte(line("delete", "a.sokolov", "secrets", "prod", "nosuch", "", code, ""))); ok {
			t.Errorf("a write that failed with %d must not become a standalone event", code)
		}
	}
	denied, ok := f.Parse([]byte(line("delete", "a.sokolov", "secrets", "prod", "db", "", 403, "")))
	if !ok || denied.Event.Allowed {
		t.Errorf("a denied request is kept and marked: ok=%v allowed=%v", ok, denied.Event.Allowed)
	}
	failed, ok := f.Parse([]byte(line("create", "a.sokolov", "pods", "prod", "p", "", 409,
		`"policyeval.wolfee-watcher.io/event-id":"uid-3"`)))
	if !ok || failed.Event.Allowed {
		t.Errorf("the verdict of an admitted request that failed must reach kvisior: ok=%v allowed=%v", ok, failed.Event.Allowed)
	}
	if _, ok := f.Parse([]byte(line("list", "system:admin", "pods", "prod", "", "", 200, ""))); !ok {
		t.Error("system:admin is a person; its reads are kept")
	}
}

func TestEveryRotatedFileIsRecoveredAfterOutage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendLine(t, path, "")
	var down atomic.Bool
	down.Store(true)
	c := &collector{}
	tail := New(path, dir, DefaultFilter(), func(ctx context.Context, r []Record) error {
		if down.Load() {
			return errors.New("kvisior down")
		}
		return c.sink(ctx, r)
	})
	if err := tail.open(true); err != nil {
		t.Fatal(err)
	}
	defer func() { tail.file.Close() }()
	appendLine(t, path, record("a1"))
	_ = step(t, tail)
	for i, name := range []string{"b1", "c1", "d1"} {
		if err := os.Rename(path, fmt.Sprintf("%s.%d", path, i+1)); err != nil {
			t.Fatal(err)
		}
		appendLine(t, path, record(name))
		_ = step(t, tail)
	}
	down.Store(false)
	if err := step(t, tail); err != nil {
		t.Fatal(err)
	}
	if c.names() != "a1,b1,c1,d1" {
		t.Fatalf("delivered %q after an outage across three rotations", c.names())
	}
}

func TestEveryRotatedFileIsRecoveredAfterRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendLine(t, path, record("seen"))
	old := New(path, dir, DefaultFilter(), func(context.Context, []Record) error { return nil })
	if err := old.open(true); err != nil {
		t.Fatal(err)
	}
	old.saveCheckpoint(true)
	old.file.Close()
	appendLine(t, path, record("a-tail"))
	for i, name := range []string{"b1", "c1"} {
		if err := os.Rename(path, fmt.Sprintf("%s.%d", path, i+1)); err != nil {
			t.Fatal(err)
		}
		appendLine(t, path, record(name))
	}
	c := &collector{}
	restarted := New(path, dir, DefaultFilter(), c.sink)
	if err := restarted.open(true); err != nil {
		t.Fatal(err)
	}
	defer func() { restarted.file.Close() }()
	if err := step(t, restarted); err != nil {
		t.Fatal(err)
	}
	if c.names() != "a-tail,b1,c1" {
		t.Fatalf("recovered %q after a restart across two rotations", c.names())
	}
}

func TestCheckpointedFileGoneResumesFromNextRetained(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendLine(t, path, record("seen"))
	old := New(path, dir, DefaultFilter(), func(context.Context, []Record) error { return nil })
	if err := old.open(true); err != nil {
		t.Fatal(err)
	}
	old.saveCheckpoint(true)
	old.file.Close()
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, record("b1"))
	if err := os.Rename(path, path+".2"); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, record("c1"))
	if err := os.Remove(path + ".1"); err != nil {
		t.Fatal(err)
	}
	c := &collector{}
	restarted := New(path, dir, DefaultFilter(), c.sink)
	if err := restarted.open(true); err != nil {
		t.Fatal(err)
	}
	defer func() { restarted.file.Close() }()
	if err := step(t, restarted); err != nil {
		t.Fatal(err)
	}
	if c.names() != "b1,c1" {
		t.Fatalf("recovered %q when the checkpointed file was already removed", c.names())
	}
}

func TestRejectedRecordIsIsolatedAndSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendLine(t, path, "")
	c := &collector{}
	tail := New(path, dir, DefaultFilter(), func(ctx context.Context, r []Record) error {
		for _, rec := range r {
			if rec.Event.Name == "poison" {
				return fmt.Errorf("%w: http 400", ErrRejected)
			}
		}
		return c.sink(ctx, r)
	})
	if err := tail.open(true); err != nil {
		t.Fatal(err)
	}
	defer func() { tail.file.Close() }()
	for _, name := range []string{"one", "two", "poison", "three", "four"} {
		appendLine(t, path, record(name))
	}
	if err := tail.drain(context.Background()); err != nil {
		t.Fatalf("a rejected record must not stall the stream: %v", err)
	}
	if c.names() != "one,two,three,four" || tail.Stats.Rejected.Load() != 1 {
		t.Fatalf("delivered %q, rejected %d", c.names(), tail.Stats.Rejected.Load())
	}
	if tail.committed != tail.offset {
		t.Fatal("the checkpoint must move past a rejected record")
	}
}

func TestFailedBatchIsRetriedWithoutRereadingTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendLine(t, path, "")
	fail := true
	c := &collector{}
	tail := New(path, dir, DefaultFilter(), func(ctx context.Context, r []Record) error {
		if fail {
			return errors.New("kvisior down")
		}
		return c.sink(ctx, r)
	})
	if err := tail.open(true); err != nil {
		t.Fatal(err)
	}
	defer func() { tail.file.Close() }()
	for i := 0; i < 5; i++ {
		appendLine(t, path, record(fmt.Sprintf("r%d", i)))
	}
	if err := tail.drain(context.Background()); err == nil {
		t.Fatal("expected a delivery failure")
	}
	read := tail.Stats.Lines.Load()
	for i := 0; i < 3; i++ {
		if err := tail.drain(context.Background()); err == nil {
			t.Fatal("expected a delivery failure")
		}
	}
	if tail.Stats.Lines.Load() != read {
		t.Fatalf("retries re-read the file: %d lines, then %d", read, tail.Stats.Lines.Load())
	}
	if tail.committed != 0 {
		t.Fatal("the checkpoint moved before the batch was acknowledged")
	}
	fail = false
	appendLine(t, path, record("later"))
	if err := tail.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.names() != "r0,r1,r2,r3,r4,later" {
		t.Fatalf("delivered %q", c.names())
	}
}
