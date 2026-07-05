package wolfeewatcher

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

const _ = grpc.SupportPackageIsVersion9

const (
	PushService_PushEvents_FullMethodName         = "/wolfeewatcher.PushService/PushEvents"
	PushService_PushAuditEvents_FullMethodName    = "/wolfeewatcher.PushService/PushAuditEvents"
	PushService_PushSensorSnapshot_FullMethodName = "/wolfeewatcher.PushService/PushSensorSnapshot"
	PushService_PushAnomalyEvents_FullMethodName  = "/wolfeewatcher.PushService/PushAnomalyEvents"
)

type PushServiceClient interface {
	PushEvents(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[PushEventsRequest, PushAck], error)
	PushAuditEvents(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[PushAuditRequest, PushAck], error)
	PushSensorSnapshot(ctx context.Context, in *SensorSnapshotRequest, opts ...grpc.CallOption) (*PushAck, error)
	PushAnomalyEvents(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[PushAnomalyRequest, PushAck], error)
}

type pushServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPushServiceClient(cc grpc.ClientConnInterface) PushServiceClient {
	return &pushServiceClient{cc}
}

func (c *pushServiceClient) PushEvents(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[PushEventsRequest, PushAck], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &PushService_ServiceDesc.Streams[0], PushService_PushEvents_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[PushEventsRequest, PushAck]{ClientStream: stream}
	return x, nil
}

type PushService_PushEventsClient = grpc.ClientStreamingClient[PushEventsRequest, PushAck]

func (c *pushServiceClient) PushAuditEvents(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[PushAuditRequest, PushAck], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &PushService_ServiceDesc.Streams[1], PushService_PushAuditEvents_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[PushAuditRequest, PushAck]{ClientStream: stream}
	return x, nil
}

type PushService_PushAuditEventsClient = grpc.ClientStreamingClient[PushAuditRequest, PushAck]

func (c *pushServiceClient) PushSensorSnapshot(ctx context.Context, in *SensorSnapshotRequest, opts ...grpc.CallOption) (*PushAck, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(PushAck)
	err := c.cc.Invoke(ctx, PushService_PushSensorSnapshot_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pushServiceClient) PushAnomalyEvents(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[PushAnomalyRequest, PushAck], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &PushService_ServiceDesc.Streams[2], PushService_PushAnomalyEvents_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[PushAnomalyRequest, PushAck]{ClientStream: stream}
	return x, nil
}

type PushService_PushAnomalyEventsClient = grpc.ClientStreamingClient[PushAnomalyRequest, PushAck]

type PushServiceServer interface {
	PushEvents(grpc.ClientStreamingServer[PushEventsRequest, PushAck]) error
	PushAuditEvents(grpc.ClientStreamingServer[PushAuditRequest, PushAck]) error
	PushSensorSnapshot(context.Context, *SensorSnapshotRequest) (*PushAck, error)
	PushAnomalyEvents(grpc.ClientStreamingServer[PushAnomalyRequest, PushAck]) error
	mustEmbedUnimplementedPushServiceServer()
}

type UnimplementedPushServiceServer struct{}

func (UnimplementedPushServiceServer) PushEvents(grpc.ClientStreamingServer[PushEventsRequest, PushAck]) error {
	return status.Errorf(codes.Unimplemented, "method PushEvents not implemented")
}
func (UnimplementedPushServiceServer) PushAuditEvents(grpc.ClientStreamingServer[PushAuditRequest, PushAck]) error {
	return status.Errorf(codes.Unimplemented, "method PushAuditEvents not implemented")
}
func (UnimplementedPushServiceServer) PushSensorSnapshot(context.Context, *SensorSnapshotRequest) (*PushAck, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PushSensorSnapshot not implemented")
}
func (UnimplementedPushServiceServer) PushAnomalyEvents(grpc.ClientStreamingServer[PushAnomalyRequest, PushAck]) error {
	return status.Errorf(codes.Unimplemented, "method PushAnomalyEvents not implemented")
}
func (UnimplementedPushServiceServer) mustEmbedUnimplementedPushServiceServer() {}
func (UnimplementedPushServiceServer) testEmbeddedByValue()                     {}

type UnsafePushServiceServer interface {
	mustEmbedUnimplementedPushServiceServer()
}

func RegisterPushServiceServer(s grpc.ServiceRegistrar, srv PushServiceServer) {

	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&PushService_ServiceDesc, srv)
}

func _PushService_PushEvents_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PushServiceServer).PushEvents(&grpc.GenericServerStream[PushEventsRequest, PushAck]{ServerStream: stream})
}

type PushService_PushEventsServer = grpc.ClientStreamingServer[PushEventsRequest, PushAck]

func _PushService_PushAuditEvents_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PushServiceServer).PushAuditEvents(&grpc.GenericServerStream[PushAuditRequest, PushAck]{ServerStream: stream})
}

type PushService_PushAuditEventsServer = grpc.ClientStreamingServer[PushAuditRequest, PushAck]

func _PushService_PushSensorSnapshot_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SensorSnapshotRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PushServiceServer).PushSensorSnapshot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PushService_PushSensorSnapshot_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PushServiceServer).PushSensorSnapshot(ctx, req.(*SensorSnapshotRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PushService_PushAnomalyEvents_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PushServiceServer).PushAnomalyEvents(&grpc.GenericServerStream[PushAnomalyRequest, PushAck]{ServerStream: stream})
}

type PushService_PushAnomalyEventsServer = grpc.ClientStreamingServer[PushAnomalyRequest, PushAck]

var PushService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "wolfeewatcher.PushService",
	HandlerType: (*PushServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PushSensorSnapshot",
			Handler:    _PushService_PushSensorSnapshot_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "PushEvents",
			Handler:       _PushService_PushEvents_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "PushAuditEvents",
			Handler:       _PushService_PushAuditEvents_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "PushAnomalyEvents",
			Handler:       _PushService_PushAnomalyEvents_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "wolfeewatcher/push.proto",
}
