FROM golang:1.22-alpine AS builder
WORKDIR /repo
COPY honey-operator/ ./honey-operator/
COPY pkg/ ./pkg/
COPY honey-operator/go.work.docker ./go.work
WORKDIR /repo/honey-operator
RUN rm -rf vendor/
RUN CGO_ENABLED=0 GOOS=linux go build -o /honey-operator ./cmd/operator

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /honey-operator /usr/local/bin/honey-operator
ENTRYPOINT ["honey-operator"]
