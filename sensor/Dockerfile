FROM golang:1.22-alpine AS builder
WORKDIR /repo
COPY sensor/ ./sensor/
COPY pkg/ ./pkg/
COPY sensor/go.work.docker ./go.work
WORKDIR /repo/sensor
RUN rm -rf vendor/
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o /sensor ./cmd/sensor

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /sensor /sensor
RUN chmod +x /sensor
ENTRYPOINT ["/sensor"]
