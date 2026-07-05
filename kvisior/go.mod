module github.com/wolfee-watcher/kvisior

go 1.25.0

require (
	github.com/jackc/pgx/v5 v5.5.4
	github.com/twmb/franz-go v1.18.0
	github.com/wolfee-watcher/pkg/alerts v0.0.0
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/twmb/franz-go/pkg/kadm v1.14.0
	github.com/wolfee-watcher/pkg/authz v0.0.0
	github.com/wolfee-watcher/pkg/mtls v0.0.0
	golang.org/x/crypto v0.48.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.9.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)

replace github.com/wolfee-watcher/pkg/mtls => ../pkg/mtls

replace github.com/wolfee-watcher/pkg/alerts => ../pkg/alerts

replace github.com/wolfee-watcher/pkg/authz => ../pkg/authz

require github.com/wolfee-watcher/pkg/logging v0.0.0

replace github.com/wolfee-watcher/pkg/logging => ../pkg/logging
