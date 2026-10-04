package alerts

import (
	"context"
	"testing"
	"time"
)

func TestPushQueue_OnDropAfterRetriesExhausted(t *testing.T) {
	got := make(chan []int, 4)
	q := NewPushQueue[int]("test", 16, 8, 2, time.Millisecond, time.Second,
		func(context.Context, []int) DeliveryResult { return DeliveryRetry })
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

func TestPushQueue_OnDropOnPermanentFailure(t *testing.T) {
	got := make(chan []int, 4)
	attempts := make(chan struct{}, 8)
	q := NewPushQueue[int]("test", 16, 8, 5, time.Second, time.Second,
		func(context.Context, []int) DeliveryResult {
			attempts <- struct{}{}
			return DeliveryPermanent
		})
	defer q.Close()
	q.OnDrop(func(batch []int) { got <- batch })

	q.Push(7)

	select {
	case batch := <-got:
		if len(batch) != 1 || batch[0] != 7 {
			t.Fatalf("onDrop batch = %v, want [7]", batch)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onDrop was not invoked on permanent failure")
	}
	if len(attempts) != 1 {
		t.Fatalf("deliver called %d times, want 1 (permanent must not retry)", len(attempts))
	}
}

func TestPushQueue_BackpressuresWhenQueueFull(t *testing.T) {
	release := make(chan struct{})
	q := NewPushQueue[int]("test", 2, 1, 1, time.Millisecond, time.Second,
		func(context.Context, []int) DeliveryResult {
			<-release
			return DeliveryOK
		})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 8; i++ {
			q.Push(i)
		}
	}()
	select {
	case <-done:
		t.Fatal("producer did not experience backpressure")
	case <-time.After(2 * time.Second):
		// The producer is blocked until delivery makes progress.
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("producer remained blocked after delivery resumed")
	}
	if q.Dropped() != 0 || q.Lost() != 0 {
		t.Fatalf("backpressure lost items: dropped=%d lost=%d", q.Dropped(), q.Lost())
	}
	q.Close()
}

func TestPushQueue_SpillsToFallbackWhenFull(t *testing.T) {
	release := make(chan struct{})
	delivered := make(chan int, 16)
	q := NewPushQueue[int]("test", 2, 1, 1, time.Millisecond, time.Second,
		func(_ context.Context, batch []int) DeliveryResult {
			<-release
			for _, v := range batch {
				delivered <- v
			}
			return DeliveryOK
		})
	spilled := make(chan int, 16)
	q.OnDrop(func(batch []int) {
		for _, v := range batch {
			spilled <- v
		}
	})
	q.SpillWhenFull()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 8; i++ {
			q.Push(i)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("producer blocked although the fallback had room")
	}
	close(release)
	q.Close()
	seen := map[int]bool{}
	for len(seen) < 8 {
		select {
		case v := <-delivered:
			seen[v] = true
		case v := <-spilled:
			seen[v] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("received %d/8 items", len(seen))
		}
	}
	if q.Dropped() == 0 || q.Lost() != 0 {
		t.Fatalf("dropped=%d lost=%d", q.Dropped(), q.Lost())
	}
}

func TestPushQueue_SpillBackpressuresWhenFallbackFull(t *testing.T) {
	release := make(chan struct{})
	q := NewPushQueue[int]("test", 2, 1, 1, time.Millisecond, time.Second,
		func(context.Context, []int) DeliveryResult {
			<-release
			return DeliveryOK
		})
	q.OnDrop(func([]int) { <-release })
	q.SpillWhenFull()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 128; i++ {
			q.Push(i)
		}
	}()
	select {
	case <-done:
		t.Fatal("producer did not wait when both the queue and the fallback were full")
	case <-time.After(500 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("producer remained blocked after delivery resumed")
	}
	q.Close()
	if q.Lost() != 0 {
		t.Fatalf("lost=%d", q.Lost())
	}
}

func TestPushQueue_OnDropOnShutdown(t *testing.T) {
	got := make(chan int, 8)
	q := NewPushQueue[int]("test", 16, 8, 10, 50*time.Millisecond, 20*time.Millisecond,
		func(ctx context.Context, _ []int) DeliveryResult {
			<-ctx.Done()
			return DeliveryRetry
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

func TestClassifyHTTPStatus(t *testing.T) {
	cases := map[int]DeliveryResult{
		200: DeliveryOK,
		204: DeliveryOK,
		400: DeliveryPermanent,
		401: DeliveryRetry,
		403: DeliveryRetry,
		404: DeliveryRetry,
		413: DeliveryPermanent,
		422: DeliveryPermanent,
		429: DeliveryRetry,
		500: DeliveryRetry,
		501: DeliveryPermanent,
		503: DeliveryRetry,
	}
	for status, want := range cases {
		if got := ClassifyHTTPStatus(status); got != want {
			t.Errorf("ClassifyHTTPStatus(%d) = %s, want %s", status, got, want)
		}
	}
}
