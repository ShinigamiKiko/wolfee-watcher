package push

import (
	"testing"
	"time"
)

func TestClientQueueReleasesItemsWhenDue(t *testing.T) {
	q := newClientQueue()
	t0 := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	q.add(pendingClient{id: "a", at: t0})
	q.add(pendingClient{id: "b", at: t0.Add(time.Minute)})
	if got := q.due(t0.Add(clientRetryAfter - time.Second)); len(got) != 0 {
		t.Fatalf("nothing is due before the retry delay, got %d", len(got))
	}
	got := q.due(t0.Add(clientRetryAfter))
	if len(got) != 1 || got[0].id != "a" {
		t.Fatalf("due = %+v, want only a", got)
	}
	if got := q.due(t0.Add(time.Minute + clientRetryAfter)); len(got) != 1 || got[0].id != "b" {
		t.Fatalf("due = %+v, want only b", got)
	}
}

func TestClientQueueIsBounded(t *testing.T) {
	q := newClientQueue()
	t0 := time.Now()
	for i := 0; i < clientQueueCap+10; i++ {
		q.add(pendingClient{at: t0})
	}
	if len(q.items) != clientQueueCap {
		t.Fatalf("queue length = %d, want %d", len(q.items), clientQueueCap)
	}
}
