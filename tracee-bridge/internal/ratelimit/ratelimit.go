package ratelimit

import (
	"sync"
	"time"
)

type TokenBucket struct {
	tokens   float64
	lastFill time.Time
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*TokenBucket
	burst   float64
	ratePS  float64
}

func New(burst int, perMin int) *Limiter {
	return &Limiter{
		buckets: make(map[string]*TokenBucket),
		burst:   float64(burst),
		ratePS:  float64(perMin) / 60.0,
	}
}

const maxBuckets = 50000

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			l.evictStale(now)
		}
		b = &TokenBucket{tokens: l.burst, lastFill: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * l.ratePS
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastFill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) evictStale(now time.Time) {
	if l.ratePS <= 0 {
		return
	}
	fullRefill := time.Duration(l.burst/l.ratePS*float64(time.Second)) + time.Second
	for k, b := range l.buckets {
		if now.Sub(b.lastFill) >= fullRefill {
			delete(l.buckets, k)
		}
	}
}

func (l *Limiter) Reset() {
	l.mu.Lock()
	l.buckets = make(map[string]*TokenBucket)
	l.mu.Unlock()
}

func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
