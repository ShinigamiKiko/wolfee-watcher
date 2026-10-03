FROM golang:1.25-alpine AS build
WORKDIR /repo
COPY central/ ./central/
COPY pkg/logging/ ./pkg/logging/
COPY pkg/auditrules/ ./pkg/auditrules/
WORKDIR /repo/central
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /central-migrate ./cmd/migrate

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /central-migrate /central-migrate
USER 65534:65534
ENTRYPOINT ["/central-migrate"]
