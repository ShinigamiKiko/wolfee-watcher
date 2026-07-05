package wolfeewatcher

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)

	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PushEventsRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Events        [][]byte               `protobuf:"bytes,1,rep,name=events,proto3" json:"events,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PushEventsRequest) Reset() {
	*x = PushEventsRequest{}
	mi := &file_wolfeewatcher_push_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PushEventsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushEventsRequest) ProtoMessage() {}

func (x *PushEventsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_wolfeewatcher_push_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (*PushEventsRequest) Descriptor() ([]byte, []int) {
	return file_wolfeewatcher_push_proto_rawDescGZIP(), []int{0}
}

func (x *PushEventsRequest) GetEvents() [][]byte {
	if x != nil {
		return x.Events
	}
	return nil
}

type PushAuditRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Events        [][]byte               `protobuf:"bytes,1,rep,name=events,proto3" json:"events,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PushAuditRequest) Reset() {
	*x = PushAuditRequest{}
	mi := &file_wolfeewatcher_push_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PushAuditRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushAuditRequest) ProtoMessage() {}

func (x *PushAuditRequest) ProtoReflect() protoreflect.Message {
	mi := &file_wolfeewatcher_push_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (*PushAuditRequest) Descriptor() ([]byte, []int) {
	return file_wolfeewatcher_push_proto_rawDescGZIP(), []int{1}
}

func (x *PushAuditRequest) GetEvents() [][]byte {
	if x != nil {
		return x.Events
	}
	return nil
}

type SensorSnapshotRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Snapshot      []byte                 `protobuf:"bytes,1,opt,name=snapshot,proto3" json:"snapshot,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SensorSnapshotRequest) Reset() {
	*x = SensorSnapshotRequest{}
	mi := &file_wolfeewatcher_push_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SensorSnapshotRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SensorSnapshotRequest) ProtoMessage() {}

func (x *SensorSnapshotRequest) ProtoReflect() protoreflect.Message {
	mi := &file_wolfeewatcher_push_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (*SensorSnapshotRequest) Descriptor() ([]byte, []int) {
	return file_wolfeewatcher_push_proto_rawDescGZIP(), []int{2}
}

func (x *SensorSnapshotRequest) GetSnapshot() []byte {
	if x != nil {
		return x.Snapshot
	}
	return nil
}

type PushAnomalyRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Events        [][]byte               `protobuf:"bytes,1,rep,name=events,proto3" json:"events,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PushAnomalyRequest) Reset() {
	*x = PushAnomalyRequest{}
	mi := &file_wolfeewatcher_push_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PushAnomalyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushAnomalyRequest) ProtoMessage() {}

func (x *PushAnomalyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_wolfeewatcher_push_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (*PushAnomalyRequest) Descriptor() ([]byte, []int) {
	return file_wolfeewatcher_push_proto_rawDescGZIP(), []int{3}
}

func (x *PushAnomalyRequest) GetEvents() [][]byte {
	if x != nil {
		return x.Events
	}
	return nil
}

type PushAck struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Accepted      uint32                 `protobuf:"varint,1,opt,name=accepted,proto3" json:"accepted,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PushAck) Reset() {
	*x = PushAck{}
	mi := &file_wolfeewatcher_push_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PushAck) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushAck) ProtoMessage() {}

func (x *PushAck) ProtoReflect() protoreflect.Message {
	mi := &file_wolfeewatcher_push_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (*PushAck) Descriptor() ([]byte, []int) {
	return file_wolfeewatcher_push_proto_rawDescGZIP(), []int{4}
}

func (x *PushAck) GetAccepted() uint32 {
	if x != nil {
		return x.Accepted
	}
	return 0
}

var File_wolfeewatcher_push_proto protoreflect.FileDescriptor

const file_wolfeewatcher_push_proto_rawDesc = "" +
	"\n" +
	"\x18wolfeewatcher/push.proto\x12\rwolfeewatcher\"+\n" +
	"\x11PushEventsRequest\x12\x16\n" +
	"\x06events\x18\x01 \x03(\fR\x06events\"*\n" +
	"\x10PushAuditRequest\x12\x16\n" +
	"\x06events\x18\x01 \x03(\fR\x06events\"3\n" +
	"\x15SensorSnapshotRequest\x12\x1a\n" +
	"\bsnapshot\x18\x01 \x01(\fR\bsnapshot\",\n" +
	"\x12PushAnomalyRequest\x12\x16\n" +
	"\x06events\x18\x01 \x03(\fR\x06events\"%\n" +
	"\aPushAck\x12\x1a\n" +
	"\baccepted\x18\x01 \x01(\rR\baccepted2\xcb\x02\n" +
	"\vPushService\x12H\n" +
	"\n" +
	"PushEvents\x12 .wolfeewatcher.PushEventsRequest\x1a\x16.wolfeewatcher.PushAck(\x01\x12L\n" +
	"\x0fPushAuditEvents\x12\x1f.wolfeewatcher.PushAuditRequest\x1a\x16.wolfeewatcher.PushAck(\x01\x12R\n" +
	"\x12PushSensorSnapshot\x12$.wolfeewatcher.SensorSnapshotRequest\x1a\x16.wolfeewatcher.PushAck\x12P\n" +
	"\x11PushAnomalyEvents\x12!.wolfeewatcher.PushAnomalyRequest\x1a\x16.wolfeewatcher.PushAck(\x01BCZAgithub.com/wolfee-watcher/kvisior/api/wolfeewatcher;wolfeewatcherb\x06proto3"

var (
	file_wolfeewatcher_push_proto_rawDescOnce sync.Once
	file_wolfeewatcher_push_proto_rawDescData []byte
)

func file_wolfeewatcher_push_proto_rawDescGZIP() []byte {
	file_wolfeewatcher_push_proto_rawDescOnce.Do(func() {
		file_wolfeewatcher_push_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_wolfeewatcher_push_proto_rawDesc), len(file_wolfeewatcher_push_proto_rawDesc)))
	})
	return file_wolfeewatcher_push_proto_rawDescData
}

var file_wolfeewatcher_push_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_wolfeewatcher_push_proto_goTypes = []any{
	(*PushEventsRequest)(nil),
	(*PushAuditRequest)(nil),
	(*SensorSnapshotRequest)(nil),
	(*PushAnomalyRequest)(nil),
	(*PushAck)(nil),
}
var file_wolfeewatcher_push_proto_depIdxs = []int32{
	0,
	1,
	2,
	3,
	4,
	4,
	4,
	4,
	4,
	0,
	0,
	0,
	0,
}

func init() { file_wolfeewatcher_push_proto_init() }
func file_wolfeewatcher_push_proto_init() {
	if File_wolfeewatcher_push_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_wolfeewatcher_push_proto_rawDesc), len(file_wolfeewatcher_push_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_wolfeewatcher_push_proto_goTypes,
		DependencyIndexes: file_wolfeewatcher_push_proto_depIdxs,
		MessageInfos:      file_wolfeewatcher_push_proto_msgTypes,
	}.Build()
	File_wolfeewatcher_push_proto = out.File
	file_wolfeewatcher_push_proto_goTypes = nil
	file_wolfeewatcher_push_proto_depIdxs = nil
}
