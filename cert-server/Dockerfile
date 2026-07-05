FROM golang:1.22-alpine AS builder
WORKDIR /repo
COPY cert-server/ ./cert-server/
COPY pkg/ ./pkg/
COPY cert-server/go.work.docker ./go.work
WORKDIR /repo/cert-server
RUN rm -rf vendor/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /cert-server ./cmd/

FROM alpine:3.19 AS ca-certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=ca-certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /cert-server /cert-server
ENTRYPOINT ["/cert-server"]
