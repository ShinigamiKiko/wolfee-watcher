package baseline

import (
	"context"
	"time"
)

type ConnIndicator struct {
	SrcEntity Entity
	DstEntity Entity
	DstPort   uint32
	Protocol  Protocol
	FlowTS    time.Time
}

type EvaluateResult int

const (
	ResultObserving EvaluateResult = iota
	ResultKnown
	ResultAnomaly
)

func (r EvaluateResult) String() string {
	switch r {
	case ResultObserving:
		return "observing"
	case ResultKnown:
		return "known"
	default:
		return "anomaly"
	}
}

func (s *Store) shouldUpdate(srcDep, dstDep string, flowTS time.Time) bool {
	compareTime := flowTS
	if compareTime.IsZero() {
		compareTime = time.Now()
	}
	atLeastOneInObservation := false
	for _, depKey := range []string{srcDep, dstDep} {
		if depKey == "" {
			continue
		}
		b := s.baselines[depKey]
		if b == nil || b.UserLocked {
			return false
		}
		if b.ObservationPeriodEnd.After(compareTime) {
			atLeastOneInObservation = true
		}
	}
	return atLeastOneInObservation
}

func (s *Store) maybeAddPeer(depKey string, p Peer, modified map[string]struct{}) {
	b := s.baselines[depKey]
	if b == nil {
		return
	}
	if _, forbidden := b.ForbiddenPeers[p]; forbidden {
		return
	}
	if _, exists := b.BaselinePeers[p]; exists {
		return
	}
	b.BaselinePeers[p] = struct{}{}
	modified[depKey] = struct{}{}
}

func (s *Store) ProcessFlowUpdate(ctx context.Context, conn ConnIndicator) EvaluateResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range []Entity{conn.SrcEntity, conn.DstEntity} {
		if _, valid := ValidPeerEntityTypes[e.Type]; !valid || e.ID == "" {
			return ResultKnown
		}
	}

	srcDepKey := s.ensureBaseline(conn.SrcEntity)
	dstDepKey := s.ensureBaseline(conn.DstEntity)
	anonSrc := AnonymizeExternalDiscoveredEntity(conn.SrcEntity)
	anonDst := AnonymizeExternalDiscoveredEntity(conn.DstEntity)
	if !s.shouldUpdate(srcDepKey, dstDepKey, conn.FlowTS) {
		return s.classifyLockedFlow(srcDepKey, dstDepKey, conn, anonSrc, anonDst)
	}

	modified := make(map[string]struct{})
	if conn.SrcEntity.Type == EntityDeployment && srcDepKey != "" {
		s.maybeAddPeer(srcDepKey, Peer{
			IsIngress: false,
			Entity:    anonDst,
			DstPort:   conn.DstPort,
			Protocol:  conn.Protocol,
			CidrBlock: cidrOf(anonDst),
		}, modified)
	}
	if conn.DstEntity.Type == EntityDeployment && dstDepKey != "" {
		s.maybeAddPeer(dstDepKey, Peer{
			IsIngress: true,
			Entity:    anonSrc,
			DstPort:   conn.DstPort,
			Protocol:  conn.Protocol,
			CidrBlock: cidrOf(anonSrc),
		}, modified)
	}
	if len(modified) > 0 {
		s.markDirty(modified)
	}
	return ResultObserving
}

func (s *Store) classifyLockedFlow(srcDepKey, dstDepKey string, conn ConnIndicator, anonSrc, anonDst Entity) EvaluateResult {
	if conn.SrcEntity.Type == EntityDeployment && srcDepKey != "" {
		if s.isUnknownLockedPeer(srcDepKey, Peer{IsIngress: false, Entity: anonDst, DstPort: conn.DstPort, Protocol: conn.Protocol, CidrBlock: cidrOf(anonDst)}) {
			return ResultAnomaly
		}
	}
	if conn.DstEntity.Type == EntityDeployment && dstDepKey != "" {
		if s.isUnknownLockedPeer(dstDepKey, Peer{IsIngress: true, Entity: anonSrc, DstPort: conn.DstPort, Protocol: conn.Protocol, CidrBlock: cidrOf(anonSrc)}) {
			return ResultAnomaly
		}
	}
	return ResultKnown
}

func (s *Store) isUnknownLockedPeer(depKey string, p Peer) bool {
	b := s.baselines[depKey]
	if b == nil {
		return false
	}

	if !b.UserLocked && b.ObservationPeriodEnd.After(time.Now()) {
		return false
	}
	_, known := b.BaselinePeers[p]
	return !known
}
