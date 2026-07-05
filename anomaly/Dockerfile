FROM golang:1.22-alpine AS builder
WORKDIR /repo
COPY anomaly/ ./anomaly/
COPY pkg/ ./pkg/
COPY anomaly/go.work.docker ./go.work
WORKDIR /repo/anomaly
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /anomaly-detector ./cmd/detector

FROM alpine:3.19
RUN apk add --no-cache ca-certificates curl wget
COPY --from=builder /anomaly-detector /anomaly-detector
ENTRYPOINT ["/anomaly-detector"]
