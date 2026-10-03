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
	"github.com/wolfee-watcher/kvisior/internal/auditengine"
	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/rules"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type sysViolSSE struct {
	rules.Violation
	Fingerprint string `json:"fingerprint"`
}

const maxConcurrentWrites = 50

type PushServer struct {
	pb.UnimplementedPushServiceServer
	hub      hub.Publisher
	localHub hub.Publisher
	matcher  *rules.Matcher
	audit    *auditengine.Engine
	store    *store.Store
	writeSem chan struct{}
}

func newPushServer(pub, local hub.Publisher, m *rules.Matcher, audit *auditengine.Engine, st *store.Store) *PushServer {
	return &PushServer{
		hub:      pub,
		localHub: local,
		matcher:  m,
		audit:    audit,
		store:    st,
		writeSem: make(chan struct{}, maxConcurrentWrites),
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
					s.hub.Publish(hub.Event{Cluster: clusterctx.ForGRPC(stream.Context()), Type: "tracee_event", Data: raw})
				}
				for _, v := range s.matcher.Match(ev) {
					ns, _ := ev["namespace"].(string)
					pod, _ := ev["pod"].(string)
					cl := clusterctx.ForGRPC(stream.Context())
					s.store.EnsureClusterCached(cl)
					fp := store.Fingerprint(cl, v.RuleID, ns, pod)
					ruleID, ruleName, sev := v.RuleID, v.Rule, v.Sev
					rawCopy := append(json.RawMessage(nil), raw...)
					if err := s.syncWrite(stream.Context(), "syscall violation", func(ctx context.Context) error {
						return s.store.Cluster(cl).WriteViolationChecked(ctx, "syscall", ruleID, ruleName, sev, ns, pod, fp, rawCopy)
					}); err != nil {
						return err
					}
					sseData, _ := json.Marshal(sysViolSSE{Violation: v, Fingerprint: fp})
					s.hub.Publish(hub.Event{Cluster: clusterctx.ForGRPC(stream.Context()), Type: "violation", Data: sseData})
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
		if len(req.Events) == 0 {
			continue
		}
		cl := clusterctx.ForGRPC(stream.Context())
		events := make([]json.RawMessage, len(req.Events))
		for i, raw := range req.Events {
			events[i] = raw
		}
		if err := s.syncWrite(stream.Context(), "audit events", func(ctx context.Context) error {
			return s.audit.IngestEvents(ctx, cl, events)
		}); err != nil {
			return err
		}
		accepted += uint32(len(events))
	}
}

func (s *PushServer) PushSensorSnapshot(ctx context.Context, req *pb.SensorSnapshotRequest) (*pb.PushAck, error) {
	s.localHub.Publish(hub.Event{Cluster: clusterctx.ForGRPC(ctx), Type: "sensor_snapshot", Data: req.Snapshot})
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
			s.hub.Publish(hub.Event{Cluster: clusterctx.ForGRPC(stream.Context()), Type: "anomaly_event", Data: raw})
			accepted++
		}
	}
}

var allowedCallers = map[string]mtls.ServiceType{
	pb.PushService_PushEvents_FullMethodName:         mtls.TraceeBridge,
	pb.PushService_PushAuditEvents_FullMethodName:    mtls.SentryAudit,
	pb.PushService_PushSensorSnapshot_FullMethodName: mtls.Sensor,
	pb.PushService_PushAnomalyEvents_FullMethodName:  mtls.AnomalyDetector,
}

func authorize(ctx context.Context, method string) error {
	want, ok := allowedCallers[method]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "method %s is not allowed", method)
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer information")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "mTLS client certificate required")
	}
	if cn := tlsInfo.State.PeerCertificates[0].Subject.CommonName; mtls.ServiceType(cn) != want {
		return status.Errorf(codes.PermissionDenied, "caller %q is not authorised for %s", cn, method)
	}
	return nil
}

func unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := authorize(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := authorize(ss.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, ss)
}

func Start(ctx context.Context, addr string, tc credentials.TransportCredentials, pub, local hub.Publisher, m *rules.Matcher, audit *auditengine.Engine, st *store.Store) (*grpc.Server, error) {
	if tc == nil {
		slog.Warn("grpc_push_service_disabled",
			"component", "kvisior/grpc-push",
			"addr", addr,
			"reason", "no mTLS credentials")
		return nil, nil
	}

	srv := grpc.NewServer(
		grpc.Creds(tc),
		grpc.UnaryInterceptor(unaryAuth),
		grpc.StreamInterceptor(streamAuth),
	)
	pb.RegisterPushServiceServer(srv, newPushServer(pub, local, m, audit, st))

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
