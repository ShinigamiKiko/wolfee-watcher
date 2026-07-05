package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type PushQueue[T any] struct {
	name string

	ch   chan T
	done chan struct{}
	once sync.Once

	stopCtx context.Context
	stop    context.CancelFunc

	mu     sync.Mutex
	closed bool

	deliver  func(ctx context.Context, batch []T) bool
	onDrop   func(batch []T)
	maxBatch int
	attempts int
	backoff  time.Duration
	drain    time.Duration
	dropped  atomic.Int64

	errMu  sync.Mutex
	lastEr time.Time
}

func NewPushQueue[T any](name string, capacity, maxBatch, attempts int, backoff, drainTimeout time.Duration,
	deliver func(ctx context.Context, batch []T) bool) *PushQueue[T] {
	stopCtx, stop := context.WithCancel(context.Background())
	return &PushQueue[T]{
		name:     name,
		ch:       make(chan T, capacity),
		done:     make(chan struct{}),
		stopCtx:  stopCtx,
		stop:     stop,
		deliver:  deliver,
		maxBatch: maxBatch,
		attempts: attempts,
		backoff:  backoff,
		drain:    drainTimeout,
	}
}

func (q *PushQueue[T]) OnDrop(fn func(batch []T)) {
	if q == nil {
		return
	}
	q.onDrop = fn
}

func (q *PushQueue[T]) Push(item T) {
	if q == nil {
		return
	}
	q.once.Do(func() { go q.loop() })
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		q.dropped.Add(1)
		q.LogErrOnce("queue closed, dropping item")
		return
	}
	select {
	case q.ch <- item:
	default:
		q.dropped.Add(1)
		q.LogErrOnce("queue full, dropping item")
	}
}

func (q *PushQueue[T]) Close() {
	if q == nil {
		return
	}
	q.once.Do(func() { go q.loop() })
	q.mu.Lock()
	alreadyClosed := q.closed
	if !alreadyClosed {
		q.closed = true
		close(q.ch)
	}
	q.mu.Unlock()
	if alreadyClosed {
		<-q.done
		return
	}
	select {
	case <-q.done:
	case <-time.After(q.drain):
		q.stop()
		<-q.done
	}
	q.stop()
}

func (q *PushQueue[T]) loop() {
	defer close(q.done)
	for first := range q.ch {
		if q.stopCtx.Err() != nil {
			leftover := []T{first}
		flush:
			for {
				select {
				case it, ok := <-q.ch:
					if !ok {
						break flush
					}
					leftover = append(leftover, it)
				default:
					break flush
				}
			}
			q.dropped.Add(int64(len(leftover)))
			slog.Warn("push_queue_drain_deadline_exceeded",
				"queue", q.name,
				"buffered", len(leftover),
				"dropped_total", q.Dropped())
			if q.onDrop != nil {
				q.onDrop(leftover)
			}
			return
		}
		batch := []T{first}

	merge:
		for len(batch) < q.maxBatch {
			select {
			case it, ok := <-q.ch:
				if !ok {
					break merge
				}
				batch = append(batch, it)
			default:
				break merge
			}
		}
		q.deliverWithRetry(batch)
	}
}

func (q *PushQueue[T]) deliverWithRetry(batch []T) {
	backoff := q.backoff
	for attempt := 1; ; attempt++ {
		if q.deliver(q.stopCtx, batch) {
			return
		}
		if attempt >= q.attempts {
			q.dropped.Add(int64(len(batch)))
			q.LogErrOnce("dropping batch of %d after %d attempts", len(batch), q.attempts)
			if q.onDrop != nil {
				q.onDrop(batch)
			}
			return
		}
		select {
		case <-q.stopCtx.Done():
			q.dropped.Add(int64(len(batch)))
			q.LogErrOnce("shutdown mid-retry: handing batch of %d to fallback", len(batch))
			if q.onDrop != nil {
				q.onDrop(batch)
			}
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

func (q *PushQueue[T]) Len() int {
	if q == nil {
		return 0
	}
	return len(q.ch)
}

func (q *PushQueue[T]) Cap() int {
	if q == nil {
		return 0
	}
	return cap(q.ch)
}

func (q *PushQueue[T]) Dropped() int64 {
	if q == nil {
		return 0
	}
	return q.dropped.Load()
}

func (q *PushQueue[T]) LogErrOnce(format string, args ...interface{}) {
	q.errMu.Lock()
	defer q.errMu.Unlock()
	if time.Since(q.lastEr) < time.Minute {
		return
	}
	q.lastEr = time.Now()
	slog.Warn("push_queue_degraded",
		"queue", q.name,
		"message", formatMessage(format, args...),
		"buffered", q.Len(),
		"capacity", q.Cap(),
		"dropped_total", q.Dropped())
}

func formatMessage(format string, args ...interface{}) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
