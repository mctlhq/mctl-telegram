FROM golang:1.25-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG APP_VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w -X main.version=${APP_VERSION}" \
    -o /mctl-telegram ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w" -o /mctl-telegram-login ./cmd/login

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache ca-certificates && \
    addgroup -g 1000 app && \
    adduser -D -u 1000 -G app app

COPY --from=builder /mctl-telegram /usr/local/bin/mctl-telegram
COPY --from=builder /mctl-telegram-login /usr/local/bin/mctl-telegram-login

USER app:app

EXPOSE 8080

ENTRYPOINT ["mctl-telegram"]
