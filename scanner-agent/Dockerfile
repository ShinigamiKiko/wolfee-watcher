FROM golang:1.22-alpine AS build
WORKDIR /repo
COPY scanner-agent/ ./scanner-agent/
COPY pkg/ ./pkg/
COPY scanner-agent/go.work.docker ./go.work
WORKDIR /repo/scanner-agent
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /scanner-agent ./cmd/main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates curl

ARG TRIVY_VERSION=0.73.0
RUN curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      | tar -xz -C /usr/local/bin trivy && \
    /usr/local/bin/trivy --version

COPY scanner-agent/vulxml.xml /opt/bdu/vulxml.xml

COPY --from=build /scanner-agent /scanner-agent

RUN mkdir -p /trivy-cache /scan-workspace && chmod 0777 /trivy-cache /scan-workspace
ENV TRIVY_CACHE_DIR=/trivy-cache \
    TRIVY_PATH=/usr/local/bin/trivy \
    TRIVY_SKIP_VERSION_CHECK=true \
    SCANNER_SKIP_DB_WARMUP=true \
    SCANNER_ADDR=:9090 \
    SCAN_WORKSPACE_DIR=/scan-workspace \
    BDU_LOCAL_PATH=/opt/bdu/vulxml.xml
EXPOSE 9090
ENTRYPOINT ["/scanner-agent"]
