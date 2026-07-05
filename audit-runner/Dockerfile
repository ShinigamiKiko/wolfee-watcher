FROM golang:1.22-alpine AS builder
WORKDIR /repo
COPY audit-runner/ ./audit-runner/
COPY pkg/ ./pkg/
COPY audit-runner/go.work.docker ./go.work
WORKDIR /repo/audit-runner
RUN rm -rf vendor/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /audit-runner ./cmd/runner

FROM alpine:3.19 AS kube-bench-dl
ARG KUBE_BENCH_VERSION=0.8.0
RUN apk add --no-cache curl tar && \
    curl -fsSL \
      "https://github.com/aquasecurity/kube-bench/releases/download/v${KUBE_BENCH_VERSION}/kube-bench_${KUBE_BENCH_VERSION}_linux_amd64.tar.gz" \
      -o /tmp/kube-bench.tar.gz && \
    mkdir -p /tmp/bench && \
    tar -xzf /tmp/kube-bench.tar.gz -C /tmp/bench && \
    chmod +x /tmp/bench/kube-bench

FROM alpine:3.19
COPY --from=builder       /audit-runner         /audit-runner
COPY --from=kube-bench-dl /tmp/bench/kube-bench /tools/kube-bench
COPY --from=kube-bench-dl /tmp/bench/cfg        /tools/cfg
ENTRYPOINT ["/audit-runner"]
