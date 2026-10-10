package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeSensor struct {
	mu     sync.Mutex
	calls  map[string]int
	status int
}

func (f *fakeSensor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[strings.TrimPrefix(r.URL.Path, "/api/forensic/watch/")]++
	w.WriteHeader(f.status)
}

func (f *fakeSensor) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[key]
}

func newTestAggregator(t *testing.T, status int) (*Aggregator, *fakeSensor) {
	f := &fakeSensor{calls: map[string]int{}, status: status}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	a := New(nil, nil, srv.Client(), "", srv.URL, nil)
	return a, f
}

func snapshotOf(t *testing.T, pods map[string]string) json.RawMessage {
	type pod struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	}
	var list []pod
	for key, phase := range pods {
		parts := strings.SplitN(key, "/", 2)
		var p pod
		p.Metadata.Namespace, p.Metadata.Name, p.Status.Phase = parts[0], parts[1], phase
		list = append(list, p)
	}
	raw, err := json.Marshal(map[string]any{"pods": list})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFinishedAndDeletedPodsAreNeverPolled(t *testing.T) {
	a, f := newTestAggregator(t, http.StatusOK)
	if err := a.pods.update(snapshotOf(t, map[string]string{"ns/done": "Succeeded", "ns/live": "Running"})); err != nil {
		t.Fatal(err)
	}
	a.queueWatch("ns", "done")
	a.queueWatch("ns", "gone")
	a.queueWatch("ns", "live")
	now := time.Now()
	a.processWatches(context.Background(), now)

	if f.count("ns/done") != 0 {
		t.Fatal("a finished pod must not be polled")
	}
	if f.count("ns/live") != 1 {
		t.Fatalf("a running pod must be watched once, got %d", f.count("ns/live"))
	}
	if _, ok := a.pendingWatches["ns/gone"]; !ok {
		t.Fatal("a pod missing from the current snapshot waits for the next snapshot")
	}
	if err := a.pods.update(snapshotOf(t, map[string]string{"ns/live": "Running"})); err != nil {
		t.Fatal(err)
	}
	a.processWatches(context.Background(), now)
	if f.count("ns/gone") != 0 || len(a.pendingWatches) != 0 {
		t.Fatalf("a pod absent from a newer snapshot must be dropped without polling, pending=%v calls=%v", a.pendingWatches, f.calls)
	}
}

func TestPodThatAppearsInTheNextSnapshotIsWatched(t *testing.T) {
	a, f := newTestAggregator(t, http.StatusOK)
	if err := a.pods.update(snapshotOf(t, map[string]string{})); err != nil {
		t.Fatal(err)
	}
	a.queueWatch("ns", "attacker")
	a.processWatches(context.Background(), time.Now())
	if err := a.pods.update(snapshotOf(t, map[string]string{"ns/attacker": "Running"})); err != nil {
		t.Fatal(err)
	}
	a.processWatches(context.Background(), time.Now())
	if f.count("ns/attacker") != 1 || len(a.pendingWatches) != 0 {
		t.Fatalf("calls=%v pending=%v", f.calls, a.pendingWatches)
	}
}

func TestTransientFailuresBackOffAndGiveUp(t *testing.T) {
	a, f := newTestAggregator(t, http.StatusServiceUnavailable)
	if err := a.pods.update(snapshotOf(t, map[string]string{"ns/live": "Running"})); err != nil {
		t.Fatal(err)
	}
	a.queueWatch("ns", "live")
	now := time.Now()
	for i := 0; i < 20; i++ {
		a.processWatches(context.Background(), now)
	}
	if f.count("ns/live") != 1 {
		t.Fatalf("retries must wait for the backoff, got %d calls", f.count("ns/live"))
	}
	for i := 0; i < 10; i++ {
		now = now.Add(time.Hour)
		a.processWatches(context.Background(), now)
	}
	if f.count("ns/live") != watchMaxAttempts || len(a.pendingWatches) != 0 {
		t.Fatalf("expected %d attempts then give up, got %d calls pending=%v", watchMaxAttempts, f.count("ns/live"), a.pendingWatches)
	}
}

func TestNothingIsPolledBeforeTheFirstSnapshot(t *testing.T) {
	a, f := newTestAggregator(t, http.StatusOK)
	a.queueWatch("ns", "live")
	a.processWatches(context.Background(), time.Now())
	if f.count("ns/live") != 0 || len(a.pendingWatches) != 1 {
		t.Fatalf("calls=%v pending=%v", f.calls, a.pendingWatches)
	}
}
