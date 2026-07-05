package baseline

import "time"

func (s *Store) ProcessExecUpdate(ns, depName, binary string, execTS time.Time) EvaluateResult {
	if ns == "" || depName == "" || binary == "" {
		return ResultKnown
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.ensureBaseline(Entity{ID: ns + "/" + depName, Type: EntityDeployment, Name: depName})
	if key == "" {
		return ResultKnown
	}
	b := s.baselines[key]
	if b.BaselineBinaries == nil {
		b.BaselineBinaries = make(map[string]struct{})
	}

	compareTime := execTS
	if compareTime.IsZero() {
		compareTime = time.Now()
	}
	locked := b.UserLocked || !b.ObservationPeriodEnd.After(compareTime)

	if !locked {
		if _, exists := b.BaselineBinaries[binary]; !exists {
			b.BaselineBinaries[binary] = struct{}{}
			s.markDirty(map[string]struct{}{key: {}})
		}
		return ResultObserving
	}

	if _, known := b.BaselineBinaries[binary]; known {
		return ResultKnown
	}
	return ResultAnomaly
}
