FROM golang:1.22-alpine AS builder
WORKDIR /repo
COPY sentry-audit/ ./sentry-audit/
COPY pkg/ ./pkg/
COPY sentry-audit/go.work.docker ./go.work
WORKDIR /repo/sentry-audit
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /sentry-audit ./cmd/

FROM alpine:3.19 AS ca-certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=ca-certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /sentry-audit /sentry-audit
ENTRYPOINT ["/sentry-audit"]
