FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG APP_VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w -X main.version=${APP_VERSION}" \
    -o /mctl-telegram ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w" -o /mctl-telegram-login ./cmd/login && \
    CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w -X main.version=${APP_VERSION}" -o /mctl-telegram-canary ./cmd/canary

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache ca-certificates && \
    addgroup -g 1000 app && \
    adduser -D -u 1000 -G app app

COPY --from=builder /mctl-telegram /usr/local/bin/mctl-telegram
COPY --from=builder /mctl-telegram-login /usr/local/bin/mctl-telegram-login
COPY --from=builder /mctl-telegram-canary /usr/local/bin/mctl-telegram-canary

USER app:app

EXPOSE 8080

ENTRYPOINT ["mctl-telegram"]
