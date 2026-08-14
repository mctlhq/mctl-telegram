FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS builder

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
# cmd/agent-worker is NOT built here — it needs the claude CLI (Node.js +
# @anthropic-ai/claude-code) to do anything, which this Go-only image
# deliberately doesn't have. It ships in its own dedicated image built from
# Dockerfile.agent-worker at the repo root; see docs/agent-worker.md.

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
