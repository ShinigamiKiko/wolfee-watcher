FROM golang:1.22-alpine AS builder
WORKDIR /repo
COPY tracee-bridge/ ./tracee-bridge/
COPY pkg/ ./pkg/
COPY tracee-bridge/go.work.docker ./go.work
WORKDIR /repo/tracee-bridge
ENV GOWORK=/repo/go.work
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bridge ./cmd/bridge

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /bridge /bridge
ENTRYPOINT ["/bridge"]
