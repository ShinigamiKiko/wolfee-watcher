package auth

import (
	"fmt"
	"testing"
	"time"
)

func TestRL_UnknownKeyAllowed(t *testing.T) {
	m := newMgr()
	if w := m.rlCheck("alice"); w != 0 {
		t.Fatalf("unknown key: want 0, got %v", w)
	}
}

func TestRL_LockAfterMaxFailures(t *testing.T) {
	m := newMgr()
	for i := 0; i < rlMaxTries; i++ {
		if w := m.rlCheck("alice"); w != 0 {
			t.Fatalf("before lock: attempt %d should be allowed, got wait %v", i+1, w)
		}
		m.rlRecord("alice")
	}
	if w := m.rlCheck("alice"); w <= 0 {
		t.Fatalf("after %d failures: expected rate-limit, got 0", rlMaxTries)
	}
}

func TestRL_ResetClearsLock(t *testing.T) {
	m := newMgr()
	for i := 0; i < rlMaxTries; i++ {
		m.rlRecord("alice")
	}
	m.rlReset("alice")
	if w := m.rlCheck("alice"); w != 0 {
		t.Fatalf("after reset: want 0, got %v", w)
	}
}

func TestRL_ExpiredWindowResets(t *testing.T) {
	m := newMgr()
	m.rlMu.Lock()
	m.rlEntries["alice"] = &rlEntry{failures: rlMaxTries, resetAt: time.Now().Add(-time.Second)}
	m.rlMu.Unlock()

	if w := m.rlCheck("alice"); w != 0 {
		t.Fatalf("expired window: want 0, got %v", w)
	}
	m.rlMu.Lock()
	_, still := m.rlEntries["alice"]
	m.rlMu.Unlock()
	if still {
		t.Error("expired entry should be removed on check")
	}
}

func TestRL_FullMap_NewUserStillTracked(t *testing.T) {
	m := newMgr()
	for i := 0; i < rlEntriesMax; i++ {
		m.rlRecord(fmt.Sprintf("user-%d", i))
	}
	if len(m.rlEntries) != rlEntriesMax {
		t.Fatalf("setup: want %d entries, got %d", rlEntriesMax, len(m.rlEntries))
	}

	for i := 0; i < rlMaxTries; i++ {
		m.rlRecord("overflow-user")
	}

	if len(m.rlEntries) > rlEntriesMax {
		t.Fatalf("map grew beyond max: %d > %d", len(m.rlEntries), rlEntriesMax)
	}
	if w := m.rlCheck("overflow-user"); w <= 0 {
		t.Fatal("new user must be rate-limited even when map was full at insertion time")
	}
}

func TestRL_FullMap_EvictsSoonestEntry(t *testing.T) {
	m := newMgr()
	for i := 0; i < rlEntriesMax-1; i++ {
		m.rlMu.Lock()
		m.rlEntries[fmt.Sprintf("u%d", i)] = &rlEntry{failures: 1, resetAt: time.Now().Add(rlWindow)}
		m.rlMu.Unlock()
	}
	const soonKey = "soon-key"
	m.rlMu.Lock()
	m.rlEntries[soonKey] = &rlEntry{failures: 1, resetAt: time.Now().Add(time.Second)}
	m.rlMu.Unlock()

	if len(m.rlEntries) != rlEntriesMax {
		t.Fatalf("setup: want %d entries, got %d", rlEntriesMax, len(m.rlEntries))
	}

	m.rlRecord("newcomer")

	m.rlMu.Lock()
	_, soonGone := m.rlEntries[soonKey]
	_, newcomerIn := m.rlEntries["newcomer"]
	m.rlMu.Unlock()

	if soonGone {
		t.Error("soonest-expiring entry should have been evicted")
	}
	if !newcomerIn {
		t.Error("newcomer should be tracked after eviction")
	}
}
