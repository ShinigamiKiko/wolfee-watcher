package baseline

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"
)

func (s *Store) MarkForbidden(ns, depName string, p Peer) {
	s.mutateBaseline(ns, depName, func(b *BaselineInfo) {
		delete(b.BaselinePeers, p)
		b.ForbiddenPeers[p] = struct{}{}
	})
}

func (s *Store) MarkBaseline(ns, depName string, p Peer) {
	s.mutateBaseline(ns, depName, func(b *BaselineInfo) {
		b.BaselinePeers[p] = struct{}{}
		delete(b.ForbiddenPeers, p)
	})
}

func (s *Store) LockBaseline(ns, depName string) {
	s.mutateBaseline(ns, depName, func(b *BaselineInfo) {
		b.UserLocked = true
	})
}

func (s *Store) mutateBaseline(ns, depName string, fn func(*BaselineInfo)) {
	s.mu.Lock()
	key := ns + "/" + depName
	b := s.baselines[key]
	if b == nil {
		s.mu.Unlock()
		return
	}
	fn(b)
	s.mu.Unlock()
	s.markDirty(map[string]struct{}{key: {}})
}

func (s *Store) ensureBaseline(e Entity) string {
	if e.Type != EntityDeployment {
		return ""
	}
	key := e.ID
	if _, exists := s.baselines[key]; !exists {
		ns, _, ok := strings.Cut(key, "/")
		if !ok {
			log.Printf("[baseline] ensureBaseline: unexpected key format %q (expected ns/depName)", key)
			ns = ""
		}
		s.baselines[key] = &BaselineInfo{
			Namespace:            ns,
			DeploymentID:         key,
			DeploymentName:       e.Name,
			ObservationPeriodEnd: time.Now().Add(s.observationPeriod),
			BaselinePeers:        make(map[Peer]struct{}),
			ForbiddenPeers:       make(map[Peer]struct{}),
			BaselineBinaries:     make(map[string]struct{}),
		}
		log.Printf("[baseline] new baseline for %s (observing until %s)", key, s.baselines[key].ObservationPeriodEnd.Format(time.RFC3339))
	}
	return key
}

func (s *Store) persistModified(ctx context.Context, keys map[string]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range keys {
		if b := s.baselines[key]; b != nil {
			s.persistOne(ctx, key, b)
		}
	}
}

func (s *Store) persistOne(ctx context.Context, key string, b *BaselineInfo) {
	if s.pool == nil {
		return
	}
	bpJSON, err := json.Marshal(b.BaselinePeers)
	if err != nil {
		log.Printf("[baseline] persist marshal BaselinePeers %s: %v", key, err)
		return
	}
	fpJSON, err := json.Marshal(b.ForbiddenPeers)
	if err != nil {
		log.Printf("[baseline] persist marshal ForbiddenPeers %s: %v", key, err)
		return
	}
	binaries := b.BaselineBinaries
	if binaries == nil {
		binaries = map[string]struct{}{}
	}
	bbJSON, err := json.Marshal(binaries)
	if err != nil {
		log.Printf("[baseline] persist marshal BaselineBinaries %s: %v", key, err)
		return
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO network_baselines
(key, ns, dep_name, dep_id, observation_period_end, user_locked, baseline_peers, forbidden_peers, baseline_binaries, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
ON CONFLICT (key) DO UPDATE SET
observation_period_end = EXCLUDED.observation_period_end,
user_locked            = EXCLUDED.user_locked,
baseline_peers         = EXCLUDED.baseline_peers,
forbidden_peers        = EXCLUDED.forbidden_peers,
baseline_binaries      = EXCLUDED.baseline_binaries,
updated_at             = NOW()`,
		key, b.Namespace, b.DeploymentName, b.DeploymentID,
		b.ObservationPeriodEnd, b.UserLocked, bpJSON, fpJSON, bbJSON,
	)
	if err != nil {
		log.Printf("[baseline] persist error %s: %v", key, err)
	}
}

func (s *Store) markDirty(keys map[string]struct{}) {
	if s.pool == nil || len(keys) == 0 {
		return
	}
	s.dirtyMu.Lock()
	for k := range keys {
		s.dirty[k] = struct{}{}
	}
	s.dirtyMu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *Store) persistLoop() {
	for {
		select {
		case <-s.baseCtx.Done():
			s.flushDirty(context.Background())
			return
		case <-s.notify:
			timer := time.NewTimer(persistDebounce)
			select {
			case <-s.baseCtx.Done():
				timer.Stop()
				s.flushDirty(context.Background())
				return
			case <-timer.C:
			}
			ctx, cancel := context.WithTimeout(s.baseCtx, persistTimeout)
			s.flushDirty(ctx)
			cancel()
		}
	}
}

func (s *Store) flushDirty(ctx context.Context) {
	s.dirtyMu.Lock()
	if len(s.dirty) == 0 {
		s.dirtyMu.Unlock()
		return
	}
	keys := s.dirty
	s.dirty = make(map[string]struct{})
	s.dirtyMu.Unlock()
	s.persistModified(ctx, keys)
}
