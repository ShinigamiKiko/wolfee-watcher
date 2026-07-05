FROM golang:1.22-alpine AS build
WORKDIR /repo
COPY scanner-agent/ ./scanner-agent/
COPY pkg/ ./pkg/
COPY scanner-agent/go.work.docker ./go.work
WORKDIR /repo/scanner-agent
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /scanner-agent ./cmd/main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates curl

ARG GRYPE_VERSION=0.111.1
RUN curl -sSfL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
      | tar -xz -C /usr/local/bin grype && \
    /usr/local/bin/grype version

COPY scanner-agent/vulxml.xml /opt/bdu/vulxml.xml

COPY --from=build /scanner-agent /scanner-agent

RUN mkdir -p /grype-cache /scan-workspace && chmod 0777 /grype-cache /scan-workspace
ENV GRYPE_DB_CACHE_DIR=/grype-cache \
    GRYPE_PATH=/usr/local/bin/grype \
    GRYPE_SKIP_DB_UPDATE=true \
    SCANNER_ADDR=:9090 \
    SCAN_WORKSPACE_DIR=/scan-workspace \
    BDU_LOCAL_PATH=/opt/bdu/vulxml.xml
EXPOSE 9090
ENTRYPOINT ["/scanner-agent"]
