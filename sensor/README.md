# Wolfee-Watcher Sensor

K8s CIS compliance sensor — watches the Kubernetes API in real-time and logs security findings.

## Quick Start

### With a real cluster
```bash
go mod tidy
go run ./cmd/sensor/
# or with explicit kubeconfig:
go run ./cmd/sensor/ -kubeconfig ~/.kube/config
```

### Without a cluster (mock mode)
```bash
go mod tidy
go run ./cmd/sensor/ -mock
```

Mock mode spins up a fake K8s client pre-loaded with intentional misconfigs:
- Privileged pod + hostPID in `prod`
- hostNetwork + secret as env var in `staging`
- Dangerous capabilities (NET_ADMIN, SYS_PTRACE) in `monitoring`
- Wildcard RBAC role + cluster-admin binding

## What it checks

| CIS ID     | Check                                        | Severity |
|------------|----------------------------------------------|----------|
| CIS-5.2.1  | Privileged containers                        | CRITICAL |
| CIS-5.2.2  | hostPID                                      | CRITICAL |
| CIS-5.2.3  | hostIPC                                      | CRITICAL |
| CIS-5.2.4  | hostNetwork                                  | HIGH     |
| CIS-5.2.6  | Running as root                              | HIGH     |
| CIS-5.2.8  | Dangerous capabilities (NET_ADMIN etc)       | HIGH     |
| CIS-5.1.1  | cluster-admin bindings                       | CRITICAL |
| CIS-5.1.2  | Wildcard verbs/resources in RBAC             | HIGH     |
| CIS-5.1.6  | Default SA automount token                   | MEDIUM   |
| CIS-5.3.2  | Missing NetworkPolicy in namespace           | HIGH     |
| CIS-5.4.1  | Secrets mounted as env vars                  | MEDIUM   |
| CIS-5.7.4  | Read-only root filesystem not set            | LOW      |

## Output format

Two modes:
- **Human-readable** (default) — colored terminal output
- **JSON** (`-json` flag) — one JSON line per finding, ready to pipe into NATS

## Project structure

```
sensor/
├── cmd/sensor/main.go          — entrypoint, client setup, mock data
├── internal/
│   ├── checks/checks.go        — all CIS check functions
│   ├── watcher/watcher.go      — K8s informers + event handlers
│   └── logger/logger.go        — colored output + JSON mode
└── go.mod
```

## Next step

Replace fake client with real NATS publisher:
```go
// in watcher.go, instead of logger.LogFinding(f):
nats.Publish("compliance.findings", json.Marshal(f))
```
