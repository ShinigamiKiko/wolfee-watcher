package logtail

import (
	"context"
	"encoding/json"
	"github.com/wolfee-watcher/sentry-audit/internal/webhook"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRotationDuringRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendLine(t, path, line("create", "alice", "configmaps", "prod", "old", "", 201, "")+"\n")
	old := New(path, dir, DefaultFilter(), func(context.Context, []Record) error { return nil })
	if err := old.open(true); err != nil {
		t.Fatal(err)
	}
	old.saveCheckpoint(true)
	old.file.Close()
	appendLine(t, path, line("create", "alice", "configmaps", "prod", "unread-old", "", 201, "")+"\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, line("create", "alice", "configmaps", "prod", "during-downtime", "", 201, "")+"\n")
	if err := syscall.Mkfifo(filepath.Join(dir, "00-fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &collector{}
	restarted := New(path, dir, DefaultFilter(), c.sink)
	if err := restarted.open(true); err != nil {
		t.Fatal(err)
	}
	defer func() { restarted.file.Close() }()
	if err := restarted.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !restarted.rotated() {
		t.Fatal("expected recovered old inode")
	}
	if err := restarted.open(false); err != nil {
		t.Fatal(err)
	}
	if err := restarted.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.names() != "unread-old,during-downtime" {
		t.Fatalf("recovered %q", c.names())
	}
}

type blockedTransport struct{}

func (r *blockedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestCheckpointWaitsForDeliveryAck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendLine(t, path, "")
	fwd := webhook.NewLogForwarder("http://kvisior.invalid", "", &blockedTransport{})
	defer fwd.Close()
	tail := New(path, dir, DefaultFilter(), func(ctx context.Context, records []Record) error {
		items := make([]json.RawMessage, 0, len(records))
		for _, rec := range records {
			raw, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			items = append(items, raw)
		}
		return fwd.Send(ctx, items)
	})
	if err := tail.open(true); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, line("create", "alice", "configmaps", "prod", "unacknowledged", "", 201, "")+"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := tail.drain(ctx); err == nil {
		t.Fatal("expected delivery failure")
	}
	tail.saveCheckpoint(true)
	tail.file.Close()
	c := &collector{}
	restarted := New(path, dir, DefaultFilter(), c.sink)
	if err := restarted.open(true); err != nil {
		t.Fatal(err)
	}
	defer restarted.file.Close()
	if err := restarted.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.names() != "unacknowledged" {
		t.Fatalf("recovered %q", c.names())
	}
}

func TestFailedBatchKeepsEarlierAck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendLine(t, path, "")
	calls := 0
	tail := New(path, dir, DefaultFilter(), func(context.Context, []Record) error {
		calls++
		if calls == 2 {
			return context.DeadlineExceeded
		}
		return nil
	})
	if err := tail.open(true); err != nil {
		t.Fatal(err)
	}
	defer tail.file.Close()
	for i := 0; i < maxBatch+1; i++ {
		appendLine(t, path, line("create", "alice", "configmaps", "prod", "record", "", 201, "")+"\n")
	}
	if err := tail.drain(context.Background()); err == nil {
		t.Fatal("expected failed second batch")
	}
	tail.saveCheckpoint(true)
	c := &collector{}
	restarted := New(path, dir, DefaultFilter(), c.sink)
	if err := restarted.open(true); err != nil {
		t.Fatal(err)
	}
	defer restarted.file.Close()
	if err := restarted.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.recs) != 1 {
		t.Fatalf("recovered %d events, want only the unacknowledged batch", len(c.recs))
	}
}
