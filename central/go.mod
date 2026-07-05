module github.com/wolfee-watcher/central

go 1.25.0

require (
	github.com/jackc/pgx/v5 v5.5.4
	golang.org/x/crypto v0.48.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.34.0 // indirect
)

require github.com/wolfee-watcher/pkg/logging v0.0.0

replace github.com/wolfee-watcher/pkg/logging => ../pkg/logging
