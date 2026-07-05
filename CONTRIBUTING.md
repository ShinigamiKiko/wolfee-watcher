# Contributing

Thanks for taking the time. This is a Go + React monorepo deployed via Helm.

## Layout

- Each service is its own Go module (`anomaly/`, `kvisior/`, `scanner-agent/`, …).
- Shared libraries live under `pkg/` (`pkg/mtls`, `pkg/alerts`, `pkg/authz`,
  `pkg/httputil`, …), each a module wired into consumers with
  `replace github.com/wolfee-watcher/pkg/<x> => ../pkg/<x>`.
- The React UI ships inside `kvisior` (embedded `dist/`).
- Deployment is Helm-only — `helm/` is the single source of truth.

## Building

```bash
# per service
cd <service> && go build ./... && go test ./...

# images (single-node dev import into containerd)
./1.sh
```

If you add or move a shared package, update each consumer's `go.mod`
(`require` + `replace`) and run `go mod tidy` in that module.

## Conventions

- Structured logging via `log/slog`, with a `component` key
  (`"<service>/<part>"`) on every line.
- mTLS is mandatory between services — new endpoints go behind
  `mtls.RequireService*`; anything reachable from the UI goes through the
  `kvisior` gateway, which sets the trusted `X-Acting-User` / `X-Acting-Role`
  headers. Never trust those headers from an inbound request.
- Config comes from env vars with sane defaults; invalid values log a warning
  and fall back rather than crashing.
- Keep changes formatted with `gofmt`.

## Pull requests

- One focused change per PR, with a short description of the why.
- Include tests for new behaviour where practical.
- Note any new env var, Helm value, or DB migration in the PR body.

## Security

Please do not open public issues for vulnerabilities — see
[`SECURITY.md`](SECURITY.md).
