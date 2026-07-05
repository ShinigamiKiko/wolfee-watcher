package alerts

import (
	"context"
	"testing"
	"time"
)

func TestPushQueue_OnDropAfterRetriesExhausted(t *testing.T) {
	got := make(chan []int, 4)
	q := NewPushQueue[int]("test", 16, 8, 2, time.Millisecond, time.Second,
		func(context.Context, []int) bool { return false })
	defer q.Close()
	q.OnDrop(func(batch []int) { got <- batch })

	q.Push(42)

	select {
	case batch := <-got:
		if len(batch) != 1 || batch[0] != 42 {
			t.Fatalf("onDrop batch = %v, want [42]", batch)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onDrop was not invoked after retries exhausted")
	}
}

func TestPushQueue_OnDropOnShutdown(t *testing.T) {
	got := make(chan int, 8)
	q := NewPushQueue[int]("test", 16, 8, 10, 50*time.Millisecond, 20*time.Millisecond,
		func(ctx context.Context, _ []int) bool {
			<-ctx.Done()
			return false
		})
	q.OnDrop(func(batch []int) {
		for _, v := range batch {
			got <- v
		}
	})

	q.Push(1)
	q.Push(2)
	time.Sleep(10 * time.Millisecond)
	q.Close()

	seen := 0
	for seen < 2 {
		select {
		case <-got:
			seen++
		case <-time.After(2 * time.Second):
			t.Fatalf("onDrop delivered %d/2 items on shutdown", seen)
		}
	}
}
