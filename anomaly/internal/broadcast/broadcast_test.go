package broadcast

import (
	"sync"
	"testing"
	"time"
)

func TestBroadcastDelivers(t *testing.T) {
	h := New()
	ch := h.Subscribe()
	defer h.Unsubscribe(ch)

	msg := []byte(`{"kind":"test_event"}`)
	h.Broadcast(msg)

	select {
	case got := <-ch:
		if string(got) != string(msg) {
			t.Fatalf("got %q, want %q", got, msg)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: message not delivered")
	}
}

func TestBroadcastMultipleSubscribers(t *testing.T) {
	h := New()
	const n = 5
	chs := make([]chan []byte, n)
	for i := range chs {
		chs[i] = h.Subscribe()
	}
	defer func() {
		for _, ch := range chs {
			h.Unsubscribe(ch)
		}
	}()

	msg := []byte("fan-out-msg")
	h.Broadcast(msg)

	for i, ch := range chs {
		select {
		case got := <-ch:
			if string(got) != string(msg) {
				t.Fatalf("subscriber %d: got %q, want %q", i, got, msg)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: message not received", i)
		}
	}
}

func TestBroadcastSlowSubscriber(t *testing.T) {
	h := New()
	ch := h.Subscribe()
	defer h.Unsubscribe(ch)

	for i := 0; i < cap(ch); i++ {
		ch <- []byte("prefill")
	}

	done := make(chan struct{})
	go func() {
		h.Broadcast([]byte("should-drop"))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Broadcast blocked on full subscriber buffer")
	}
}

func TestUnsubscribeClosesChannel(t *testing.T) {
	h := New()
	ch := h.Subscribe()
	h.Unsubscribe(ch)

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closed after Unsubscribe")
		}
	case <-time.After(time.Second):
		t.Fatal("channel not closed after Unsubscribe")
	}
}

func TestSubscribeAfterBroadcastReceivesNothing(t *testing.T) {
	h := New()
	h.Broadcast([]byte("before-subscribe"))

	ch := h.Subscribe()
	defer h.Unsubscribe(ch)

	select {
	case msg := <-ch:
		t.Fatalf("subscriber received stale message: %q", msg)
	case <-time.After(50 * time.Millisecond):

	}
}

func TestBroadcastRace(t *testing.T) {
	h := New()
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ch := h.Subscribe()

				go func(c chan []byte) {
					for range c {
					}
				}(ch)
				h.Broadcast([]byte("event"))
				h.Unsubscribe(ch)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			h.Broadcast([]byte("tick"))
		}
	}()

	wg.Wait()
}
