FROM node:20-alpine AS ui
WORKDIR /app
COPY kvisior/package*.json ./
RUN npm ci --silent
COPY kvisior/ ./
RUN npm run build

FROM golang:1.25-alpine AS server
WORKDIR /repo
COPY kvisior/ ./kvisior/
COPY pkg/ ./pkg/
COPY kvisior/go.work.docker ./go.work
COPY --from=ui /app/dist/ ./kvisior/dist/
WORKDIR /repo/kvisior
RUN rm -rf vendor/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /kvisior .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=server /kvisior /kvisior
EXPOSE 8080
ENTRYPOINT ["/kvisior"]
