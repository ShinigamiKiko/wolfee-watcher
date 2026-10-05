package alerts

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpoolSurvivesProcessCrash(t *testing.T) {
	if dir := os.Getenv("SPOOL_CRASH_TEST_DIR"); dir != "" {
		q, err := NewDiskSpool(dir, 4096, func(ctx context.Context, _ []json.RawMessage) error { <-ctx.Done(); return ctx.Err() })
		if err != nil {
			os.Exit(2)
		}
		if err = q.Enqueue(context.Background(), json.RawMessage(`{"id":"durable"}`)); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	dir := t.TempDir()
	child := exec.Command(os.Args[0], "-test.run=^TestSpoolSurvivesProcessCrash$")
	child.Env = append(os.Environ(), "SPOOL_CRASH_TEST_DIR="+dir)
	if out, err := child.CombinedOutput(); err != nil {
		t.Fatalf("crash helper: %v %s", err, out)
	}
	delivered := make(chan string, 1)
	q, err := NewDiskSpool(dir, 4096, func(_ context.Context, items []json.RawMessage) error { delivered <- string(items[0]); return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	select {
	case raw := <-delivered:
		if raw != `{"id":"durable"}` {
			t.Fatal(raw)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("persisted event did not recover")
	}
}
func TestSpoolDoesNotWaitForRemoteAndRetainsCapacity(t *testing.T) {
	q, err := NewDiskSpool(t.TempDir(), spoolBlock, func(ctx context.Context, _ []json.RawMessage) error { <-ctx.Done(); return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = q.Enqueue(ctx, json.RawMessage(`{"id":"one"}`)); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("admission waited for remote")
	}
	raw := json.RawMessage(`{"id":"this-record-is-larger-than-the-capacity-remaining-in-the-spool-after-the-first-record"}`)
	if err = q.Enqueue(ctx, raw); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("capacity: %v", err)
	}
	if status := q.Status(); status.Pending != 1 || status.Rejected == 0 || !status.Durable {
		t.Fatalf("status %+v", status)
	}
}
func TestSpoolReplayKeepsOrderAndExclusiveOwnership(t *testing.T) {
	dir := t.TempDir()
	q, err := NewDiskSpool(dir, 1<<20, func(context.Context, []json.RawMessage) error { return errors.New("offline") })
	if err != nil {
		t.Fatal(err)
	}
	if second, err := NewDiskSpool(dir, 1<<20, func(context.Context, []json.RawMessage) error { return nil }); err == nil {
		second.Close()
		t.Fatal("two owners accepted")
	}
	for _, raw := range []string{`{"id":1}`, `{"id":2}`, `{"id":3}`} {
		if err = q.Enqueue(context.Background(), json.RawMessage(raw)); err != nil {
			t.Fatal(err)
		}
	}
	q.Close()
	var mu sync.Mutex
	got := []string{}
	q, err = NewDiskSpool(dir, 1<<20, func(_ context.Context, items []json.RawMessage) error {
		mu.Lock()
		defer mu.Unlock()
		for _, raw := range items {
			got = append(got, string(raw))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	deadline := time.Now().Add(3 * time.Second)
	for q.Status().Pending > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 || got[0] != `{"id":1}` || got[1] != `{"id":2}` || got[2] != `{"id":3}` {
		t.Fatalf("order: %v", got)
	}
}
func waitSpool(t *testing.T, q *DiskSpool, done func(SpoolStatus) bool) SpoolStatus {
	t.Helper()
	return waitSpoolFor(t, q, 5*time.Second, done)
}
func waitSpoolFor(t *testing.T, q *DiskSpool, timeout time.Duration, done func(SpoolStatus) bool) SpoolStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		status := q.Status()
		if done(status) {
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("spool did not settle: %+v", status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func TestSpoolIsolatesPermanentlyRejectedRecords(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000001.json"), []byte(`[{"id":"a"},{"id":"poison"},{"id":"b"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	delivered := []string{}
	q, err := NewDiskSpool(dir, 1<<20, func(_ context.Context, items []json.RawMessage) error {
		for _, raw := range items {
			if strings.Contains(string(raw), "poison") {
				return fmt.Errorf("%w: 400", ErrPermanentDelivery)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		for _, raw := range items {
			delivered = append(delivered, string(raw))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	status := waitSpool(t, q, func(s SpoolStatus) bool { return s.Pending == 0 && s.DeadFiles == 1 })
	if status.Quarantined != 1 || status.Bytes != 0 || status.DeadBytes == 0 {
		t.Fatalf("status %+v", status)
	}
	mu.Lock()
	if len(delivered) != 2 || delivered[0] != `{"id":"a"}` || delivered[1] != `{"id":"b"}` {
		t.Fatalf("delivered %v", delivered)
	}
	mu.Unlock()
	dead, err := os.ReadFile(filepath.Join(dir, spoolDeadDir, "00000000000000000001.json"))
	if err != nil || string(dead) != `[{"id":"poison"}]` {
		t.Fatalf("dead record %q %v", dead, err)
	}
	if err = q.Enqueue(context.Background(), json.RawMessage(`{"id":"after"}`)); err != nil {
		t.Fatal(err)
	}
	waitSpool(t, q, func(s SpoolStatus) bool { return s.Pending == 0 })
}
func TestSpoolQuarantinesUnreadableFileAndCountsItAgainstCapacity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000001.json"), []byte("not json at all"), 0600); err != nil {
		t.Fatal(err)
	}
	hold := func(ctx context.Context, _ []json.RawMessage) error { <-ctx.Done(); return ctx.Err() }
	q, err := NewDiskSpool(dir, 2*spoolBlock, hold)
	if err != nil {
		t.Fatal(err)
	}
	status := waitSpool(t, q, func(s SpoolStatus) bool { return s.DeadFiles == 1 })
	if status.Pending != 0 || status.DeadBytes != spoolBlock {
		t.Fatalf("status %+v", status)
	}
	if err = q.Enqueue(context.Background(), json.RawMessage(`{"id":1}`)); err != nil {
		t.Fatal(err)
	}
	if err = q.Enqueue(context.Background(), json.RawMessage(`{"id":2}`)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("dead bytes ignored by capacity: %v", err)
	}
	q.Close()
	q, err = NewDiskSpool(dir, 2*spoolBlock, hold)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if status := q.Status(); status.DeadFiles != 1 || status.DeadBytes != spoolBlock {
		t.Fatalf("dead files not recovered: %+v", status)
	}
}
func TestSpoolKeepsRecordsOnTransientFailure(t *testing.T) {
	attempts := make(chan struct{}, 16)
	q, err := NewDiskSpool(t.TempDir(), 4096, func(context.Context, []json.RawMessage) error {
		attempts <- struct{}{}
		return errors.New("503 receiver busy")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err = q.Enqueue(context.Background(), json.RawMessage(`{"id":"kept"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-attempts:
	case <-time.After(3 * time.Second):
		t.Fatal("no delivery attempt")
	}
	status := waitSpool(t, q, func(s SpoolStatus) bool { return s.LastError != "" })
	if status.Pending != 1 || status.DeadFiles != 0 || status.Quarantined != 0 {
		t.Fatalf("status %+v", status)
	}
}
func TestSpoolPersistsRecordsWhoseAdmissionTimedOut(t *testing.T) {
	q, err := NewDiskSpool(t.TempDir(), 4096, func(ctx context.Context, _ []json.RawMessage) error { <-ctx.Done(); return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = q.Enqueue(ctx, json.RawMessage(`{"id":"late"}`))
	status := waitSpool(t, q, func(s SpoolStatus) bool { return s.Pending == 1 })
	if status.Rejected != 0 {
		t.Fatalf("timed-out admission counted as lost: %+v", status)
	}
	if err != nil && status.Late != 1 {
		t.Fatalf("late admission not counted: %v %+v", err, status)
	}
}
func TestSpoolAccountsWholeFilesystemBlocks(t *testing.T) {
	q, err := NewDiskSpool(t.TempDir(), 3*spoolBlock, func(ctx context.Context, _ []json.RawMessage) error { <-ctx.Done(); return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for i := 0; i < 3; i++ {
		if err := q.Enqueue(context.Background(), json.RawMessage(`{"id":1}`)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if err := q.Enqueue(context.Background(), json.RawMessage(`{"id":1}`)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("a fourth file needs a fourth block: %v", err)
	}
	if status := q.Status(); status.Bytes != 3*spoolBlock {
		t.Fatalf("bytes %d", status.Bytes)
	}
}
func TestSpoolCompactsBacklogIntoOrderedSegments(t *testing.T) {
	dir := t.TempDir()
	var online atomic.Bool
	var mu sync.Mutex
	got := []string{}
	q, err := NewDiskSpool(dir, 1<<20, func(_ context.Context, items []json.RawMessage) error {
		if !online.Load() {
			return errors.New("receiver down")
		}
		mu.Lock()
		defer mu.Unlock()
		for _, raw := range items {
			got = append(got, string(raw))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	want := []string{}
	for i := 0; i < 40; i++ {
		raw := fmt.Sprintf(`{"id":%d}`, i)
		want = append(want, raw)
		if err := q.Enqueue(context.Background(), json.RawMessage(raw)); err != nil {
			t.Fatal(err)
		}
	}
	status := waitSpool(t, q, func(s SpoolStatus) bool { return s.Compacted >= 39 && s.Pending <= 2 })
	if status.Bytes > 2*spoolBlock {
		t.Fatalf("compaction kept %d bytes for 40 records", status.Bytes)
	}
	segments, _ := filepath.Glob(filepath.Join(dir, "*.json.gz"))
	if len(segments) == 0 {
		t.Fatal("no compressed segment written")
	}
	online.Store(true)
	waitSpool(t, q, func(s SpoolStatus) bool { return s.Pending == 0 })
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order or duplicates after compaction: %v", got)
	}
}
func TestSpoolCompactsUnderPressureWhileReceiverIsDown(t *testing.T) {
	var online atomic.Bool
	var mu sync.Mutex
	got := []string{}
	q, err := NewDiskSpool(t.TempDir(), 256*spoolBlock, func(_ context.Context, items []json.RawMessage) error {
		if !online.Load() {
			return errors.New("receiver down")
		}
		mu.Lock()
		defer mu.Unlock()
		for _, raw := range items {
			got = append(got, string(raw))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	want := []string{}
	for i := 0; i < 3000; i++ {
		raw := fmt.Sprintf(`{"id":%d,"user":"burst"}`, i)
		want = append(want, raw)
		if err := q.Enqueue(context.Background(), json.RawMessage(raw)); err != nil {
			t.Fatalf("record %d lost while compaction should keep up: %v (%+v)", i, err, q.Status())
		}
	}
	if status := q.Status(); status.Rejected != 0 || status.Bytes > 256*spoolBlock {
		t.Fatalf("status %+v", status)
	}
	online.Store(true)
	waitSpoolFor(t, q, 45*time.Second, func(s SpoolStatus) bool { return s.Pending == 0 })
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("delivered %d records, order or duplicates differ", len(got))
	}
}
func TestSpoolReadsPlainAndCompressedFilesInOrder(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000001.json"), []byte(`[{"id":1}]`), 0600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(`[{"id":2},{"id":3}]`))
	zw.Close()
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000002.json.gz"), buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := []string{}
	q, err := NewDiskSpool(dir, 1<<20, func(_ context.Context, items []json.RawMessage) error {
		mu.Lock()
		defer mu.Unlock()
		for _, raw := range items {
			got = append(got, string(raw))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	waitSpool(t, q, func(s SpoolStatus) bool { return s.Pending == 0 })
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, ",") != `{"id":1},{"id":2},{"id":3}` {
		t.Fatalf("got %v", got)
	}
}

func TestSpoolDeliversAsSoonAsTheReceiverIsBack(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	var failures atomic.Int32
	delivered := make(chan time.Time, 1)
	q, err := NewDiskSpool(t.TempDir(), 1<<20, func(context.Context, []json.RawMessage) error {
		if down.Load() {
			failures.Add(1)
			return errors.New("offline")
		}
		delivered <- time.Now()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	q.SetProbe(func(context.Context) error {
		if down.Load() {
			return errors.New("offline")
		}
		return nil
	})
	if err := q.Enqueue(context.Background(), json.RawMessage(`{"id":"late"}`)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for failures.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if failures.Load() < 4 {
		t.Fatalf("only %d attempts", failures.Load())
	}
	restored := time.Now()
	down.Store(false)
	select {
	case at := <-delivered:
		if waited := at.Sub(restored); waited > SpoolProbeInterval+time.Second {
			t.Fatalf("delivered %s after the receiver came back", waited)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("not delivered")
	}
}
