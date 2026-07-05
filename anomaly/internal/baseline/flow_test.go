package baseline

import (
	"context"
	"testing"
	"time"
)

func extEgress(dep, dstIP string, port uint32) ConnIndicator {
	return ConnIndicator{
		SrcEntity: Entity{ID: "prod/" + dep, Type: EntityDeployment, Name: dep},
		DstEntity: ExternalEntity(dstIP),
		DstPort:   port,
		Protocol:  TCP,
		FlowTS:    time.Now(),
	}
}

func TestExternalEgressKnownAfterLock(t *testing.T) {
	s := New(context.Background(), nil, time.Hour)
	ctx := context.Background()

	if got := s.ProcessFlowUpdate(ctx, extEgress("web", "203.0.113.7", 443)); got != ResultObserving {
		t.Fatalf("learn: got %v, want observing", got)
	}

	s.LockBaseline("prod", "web")

	if got := s.ProcessFlowUpdate(ctx, extEgress("web", "203.0.113.7", 443)); got != ResultKnown {
		t.Fatalf("learned flow after lock: got %v, want known", got)
	}
	if got := s.ProcessFlowUpdate(ctx, extEgress("web", "198.51.100.9", 443)); got != ResultAnomaly {
		t.Fatalf("unseen destination after lock: got %v, want anomaly", got)
	}
}

func TestUserLockEnforcesBeforeObservationEnds(t *testing.T) {
	s := New(context.Background(), nil, 24*time.Hour)
	ctx := context.Background()

	s.ProcessFlowUpdate(ctx, extEgress("api", "203.0.113.7", 443))
	s.LockBaseline("prod", "api")

	if got := s.ProcessFlowUpdate(ctx, extEgress("api", "198.51.100.9", 443)); got != ResultAnomaly {
		t.Fatalf("unseen destination after early lock: got %v, want anomaly", got)
	}
}
