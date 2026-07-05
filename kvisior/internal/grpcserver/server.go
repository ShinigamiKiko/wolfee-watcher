package grpcserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	pb "github.com/wolfee-watcher/kvisior/api/wolfeewatcher"
	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/rules"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type sysViolSSE struct {
	rules.Violation
	Fingerprint string `json:"fingerprint"`
}

type auditViolSSE struct {
	rules.AuditViolation
	Fingerprint string `json:"fingerprint"`
}

const maxConcurrentWrites = 50

type PushServer struct {
	pb.UnimplementedPushServiceServer
	hub          hub.Publisher
	localHub     hub.Publisher
	matcher      *rules.Matcher
	auditMatcher *rules.AuditMatcher
	store        *store.Store
	writeSem     chan struct{}
}

func newPushServer(pub, local hub.Publisher, m *rules.Matcher, am *rules.AuditMatcher, st *store.Store) *PushServer {
	return &PushServer{
		hub:          pub,
		localHub:     local,
		matcher:      m,
		auditMatcher: am,
		store:        st,
		writeSem:     make(chan struct{}, maxConcurrentWrites),
	}
}

func (s *PushServer) syncWrite(ctx context.Context, what string, fn func(context.Context) error) error {
	if s.store == nil {
		return nil
	}
	select {
	case s.writeSem <- struct{}{}:
		defer func() { <-s.writeSem }()
	case <-ctx.Done():
		return ctx.Err()
	default:
		slog.Warn("grpc_write_backlog_full",
			"component", "kvisior/grpc-push",
			"kind", what,
			"inflight", len(s.writeSem),
			"limit", cap(s.writeSem))
		return fmt.Errorf("write backlog full for %s", what)
	}
	wCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := fn(wCtx); err != nil {
		slog.Error("grpc_persist_failed",
			"component", "kvisior/grpc-push",
			"kind", what,
			"timeout", wCtx.Err() != nil,
			"error", err)
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

func (s *PushServer) PushEvents(stream pb.PushService_PushEventsServer) error {
	var accepted uint32
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			slog.Info("grpc_push_events_closed",
				"component", "kvisior/grpc-push",
				"stream", "PushEvents",
				"accepted", accepted)
			return stream.SendAndClose(&pb.PushAck{Accepted: accepted})
		}
		if err != nil {
			return err
		}
		for _, raw := range req.Events {
			var ev map[string]interface{}
			if json.Unmarshal(raw, &ev) == nil {
				if sc, _ := ev["syscall"].(string); s.matcher.AllowsLiveStream(sc) {
					s.hub.Publish(hub.Event{Type: "tracee_event", Data: raw})
				}
				for _, v := range s.matcher.Match(ev) {
					ns, _ := ev["namespace"].(string)
					pod, _ := ev["pod"].(string)
					fp := store.Fingerprint(v.RuleID, ns, pod, time.Now())
					ruleID, ruleName, sev := v.RuleID, v.Rule, v.Sev
					rawCopy := append(json.RawMessage(nil), raw...)
					if err := s.syncWrite(stream.Context(), "syscall violation", func(ctx context.Context) error {
						return s.store.WriteViolationChecked(ctx, "syscall", ruleID, ruleName, sev, ns, pod, fp, rawCopy)
					}); err != nil {
						return err
					}
					sseData, _ := json.Marshal(sysViolSSE{Violation: v, Fingerprint: fp})
					s.hub.Publish(hub.Event{Type: "violation", Data: sseData})
				}
			}
			accepted++
		}
	}
}

func (s *PushServer) PushAuditEvents(stream pb.PushService_PushAuditEventsServer) error {
	var accepted uint32
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			slog.Info("grpc_push_events_closed",
				"component", "kvisior/grpc-push",
				"stream", "PushAuditEvents",
				"accepted", accepted)
			return stream.SendAndClose(&pb.PushAck{Accepted: accepted})
		}
		if err != nil {
			return err
		}
		for _, raw := range req.Events {
			var ev map[string]interface{}
			if json.Unmarshal(raw, &ev) == nil {
				for _, v := range s.auditMatcher.Match(ev) {
					evTs := time.Now()
					if t, err := time.Parse(time.RFC3339, v.Timestamp); err == nil {
						evTs = t
					}
					fp := store.Fingerprint(v.RuleID, v.Namespace, v.Name, evTs)
					ruleID, policy, sev, ns, name := v.RuleID, v.Policy, v.Sev, v.Namespace, v.Name
					rawCopy := append(json.RawMessage(nil), raw...)
					if err := s.syncWrite(stream.Context(), "audit violation", func(ctx context.Context) error {
						return s.store.WriteViolationChecked(ctx, "audit", ruleID, policy, sev, ns, name, fp, rawCopy)
					}); err != nil {
						return err
					}
					sseData, _ := json.Marshal(auditViolSSE{AuditViolation: v, Fingerprint: fp})
					s.hub.Publish(hub.Event{Type: "audit_violation", Data: sseData})
				}
			}
			s.hub.Publish(hub.Event{Type: "audit_event", Data: raw})
			accepted++
		}
	}
}

func (s *PushServer) PushSensorSnapshot(_ context.Context, req *pb.SensorSnapshotRequest) (*pb.PushAck, error) {
	s.localHub.Publish(hub.Event{Type: "sensor_snapshot", Data: req.Snapshot})
	slog.Info("grpc_sensor_snapshot_received",
		"component", "kvisior/grpc-push",
		"bytes", len(req.Snapshot))
	return &pb.PushAck{Accepted: 1}, nil
}

func (s *PushServer) PushAnomalyEvents(stream pb.PushService_PushAnomalyEventsServer) error {
	var accepted uint32
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			slog.Info("grpc_push_events_closed",
				"component", "kvisior/grpc-push",
				"stream", "PushAnomalyEvents",
				"accepted", accepted)
			return stream.SendAndClose(&pb.PushAck{Accepted: accepted})
		}
		if err != nil {
			return err
		}
		for _, raw := range req.Events {
			s.hub.Publish(hub.Event{Type: "anomaly_event", Data: raw})
			accepted++
		}
	}
}

func Start(ctx context.Context, addr string, tc credentials.TransportCredentials, pub, local hub.Publisher, m *rules.Matcher, am *rules.AuditMatcher, st *store.Store) (*grpc.Server, error) {
	var opts []grpc.ServerOption
	if tc != nil {
		opts = append(opts, grpc.Creds(tc))
	}

	srv := grpc.NewServer(opts...)
	pb.RegisterPushServiceServer(srv, newPushServer(pub, local, m, am, st))

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("grpc: listen %s: %w", addr, err)
	}

	go func() {
		slog.Info("grpc_push_service_started",
			"component", "kvisior/grpc-push",
			"addr", addr,
			"mtls", tc != nil)
		if err := srv.Serve(ln); err != nil && ctx.Err() == nil {
			slog.Error("grpc_push_service_failed",
				"component", "kvisior/grpc-push",
				"addr", addr,
				"error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()

	return srv, nil
}
