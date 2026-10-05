package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDatabaseServicesStartOnceTheDatabaseRecovers(t *testing.T) {
	var checks, starts atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		whenDatabaseReady(context.Background(), func(context.Context) error {
			if checks.Add(1) < 3 {
				return errors.New("connection refused")
			}
			return nil
		}, func() { starts.Add(1) })
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("services never started after the database recovered")
	}
	if checks.Load() != 3 || starts.Load() != 1 {
		t.Fatalf("checks=%d starts=%d", checks.Load(), starts.Load())
	}
}

func TestDatabaseServicesDoNotStartAfterShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	started := false
	go func() {
		defer close(done)
		whenDatabaseReady(ctx, func(context.Context) error { return errors.New("down") }, func() { started = true })
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("waiter ignored shutdown")
	}
	if started {
		t.Fatal("started while the database was down")
	}
}
