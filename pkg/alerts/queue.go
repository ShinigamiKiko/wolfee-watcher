package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type DeliveryResult int

const (
	DeliveryOK DeliveryResult = iota
	DeliveryRetry
	DeliveryPermanent
)

func (r DeliveryResult) String() string {
	switch r {
	case DeliveryOK:
		return "ok"
	case DeliveryRetry:
		return "retry"
	case DeliveryPermanent:
		return "permanent"
	default:
		return "unknown"
	}
}

type dropHandler[T any] struct {
	fn func(batch []T)
}

type PushQueue[T any] struct {
	name string

	ch       chan T
	dropCh   chan T
	done     chan struct{}
	dropDone chan struct{}
	once     sync.Once

	stopCtx context.Context
	stop    context.CancelFunc

	mu         sync.Mutex
	closed     bool
	dropClosed bool

	deliver  func(ctx context.Context, batch []T) DeliveryResult
	onDrop   atomic.Pointer[dropHandler[T]]
	maxBatch int
	attempts int
	backoff  time.Duration
	drain    time.Duration
	dropped  atomic.Int64
	lost     atomic.Int64

	errMu  sync.Mutex
	lastEr time.Time
}

func NewPushQueue[T any](name string, capacity, maxBatch, attempts int, backoff, drainTimeout time.Duration,
	deliver func(ctx context.Context, batch []T) DeliveryResult) *PushQueue[T] {
	stopCtx, stop := context.WithCancel(context.Background())
	fallbackCap := capacity / 4
	if fallbackCap < 64 {
		fallbackCap = 64
	}
	return &PushQueue[T]{
		name:     name,
		ch:       make(chan T, capacity),
		dropCh:   make(chan T, fallbackCap),
		done:     make(chan struct{}),
		dropDone: make(chan struct{}),
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
	if fn == nil {
		q.onDrop.Store(nil)
		return
	}
	q.onDrop.Store(&dropHandler[T]{fn: fn})
}

func (q *PushQueue[T]) start() {
	go q.loop()
	go q.dropLoop()
}

func (q *PushQueue[T]) Push(item T) {
	if q == nil {
		return
	}
	q.once.Do(q.start)
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		q.dropped.Add(1)
		q.LogErrOnce("queue closed, handing item to fallback")
		q.handoffLocked(item)
		return
	}
	select {
	case q.ch <- item:
		return
	case <-q.stopCtx.Done():
		q.dropped.Add(1)
		q.LogErrOnce("queue stopped, handing item to fallback")
		q.handoffLocked(item)
	}
}

func (q *PushQueue[T]) TryPush(item T) bool {
	if q == nil {
		return false
	}
	q.once.Do(q.start)
	if !q.mu.TryLock() {
		q.lost.Add(1)
		q.dropped.Add(1)
		return false
	}
	defer q.mu.Unlock()
	if q.closed {
		q.lost.Add(1)
		q.dropped.Add(1)
		return false
	}
	select {
	case q.ch <- item:
		return true
	default:
		q.lost.Add(1)
		q.dropped.Add(1)
		return false
	}
}

func (q *PushQueue[T]) handoffLocked(item T) {
	if q.onDrop.Load() == nil || q.dropClosed {
		q.lost.Add(1)
		return
	}
	select {
	case q.dropCh <- item:
	default:
		q.lost.Add(1)
		q.LogErrOnce("fallback queue full, item lost")
	}
}

func (q *PushQueue[T]) Close() {
	if q == nil {
		return
	}
	q.once.Do(q.start)
	q.mu.Lock()
	alreadyClosed := q.closed
	if !alreadyClosed {
		q.closed = true
		close(q.ch)
	}
	q.mu.Unlock()
	if alreadyClosed {
		<-q.done
		q.waitFallbackDrain()
		return
	}
	select {
	case <-q.done:
	case <-time.After(q.drain):
		q.stop()
		<-q.done
	}
	q.stop()

	q.mu.Lock()
	if !q.dropClosed {
		q.dropClosed = true
		close(q.dropCh)
	}
	q.mu.Unlock()
	q.waitFallbackDrain()
}

func (q *PushQueue[T]) waitFallbackDrain() {
	select {
	case <-q.dropDone:
	case <-time.After(q.drain):
		slog.Warn("push_queue_fallback_drain_timeout",
			"queue", q.name,
			"pending", len(q.dropCh),
			"lost_total", q.Lost())
	}
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
			q.fanOutDrop(leftover)
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

func (q *PushQueue[T]) dropLoop() {
	defer close(q.dropDone)
	for first := range q.dropCh {
		batch := []T{first}
	merge:
		for len(batch) < q.maxBatch {
			select {
			case it, ok := <-q.dropCh:
				if !ok {
					break merge
				}
				batch = append(batch, it)
			default:
				break merge
			}
		}
		q.fanOutDrop(batch)
	}
}

func (q *PushQueue[T]) fanOutDrop(batch []T) {
	if len(batch) == 0 {
		return
	}
	h := q.onDrop.Load()
	if h == nil || h.fn == nil {
		q.lost.Add(int64(len(batch)))
		slog.Warn("push_queue_items_lost",
			"queue", q.name,
			"items", len(batch),
			"reason", "no_fallback_configured",
			"lost_total", q.Lost())
		return
	}
	h.fn(batch)
}

func (q *PushQueue[T]) deliverWithRetry(batch []T) {
	backoff := q.backoff
	for attempt := 1; ; attempt++ {
		switch q.deliver(q.stopCtx, batch) {
		case DeliveryOK:
			return
		case DeliveryPermanent:
			q.dropped.Add(int64(len(batch)))
			q.LogErrOnce("permanent delivery failure, handing batch of %d to fallback", len(batch))
			q.fanOutDrop(batch)
			return
		}
		if attempt >= q.attempts {
			q.dropped.Add(int64(len(batch)))
			q.LogErrOnce("handing batch of %d to fallback after %d attempts", len(batch), q.attempts)
			q.fanOutDrop(batch)
			return
		}
		select {
		case <-q.stopCtx.Done():
			q.dropped.Add(int64(len(batch)))
			q.LogErrOnce("shutdown mid-retry: handing batch of %d to fallback", len(batch))
			q.fanOutDrop(batch)
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

func (q *PushQueue[T]) Lost() int64 {
	if q == nil {
		return 0
	}
	return q.lost.Load()
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
		"dropped_total", q.Dropped(),
		"lost_total", q.Lost())
}

func formatMessage(format string, args ...interface{}) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
