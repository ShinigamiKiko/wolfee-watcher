FROM golang:1.22-alpine AS builder
WORKDIR /repo
COPY forensic-watcher/ ./forensic-watcher/
COPY pkg/ ./pkg/
COPY forensic-watcher/go.work.docker ./go.work
WORKDIR /repo/forensic-watcher
RUN rm -rf vendor/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /forensic-watcher ./cmd/watcher

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /forensic-watcher /forensic-watcher
EXPOSE 9090
ENTRYPOINT ["/forensic-watcher"]
