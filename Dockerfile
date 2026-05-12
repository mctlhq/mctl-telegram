FROM golang:1.25-alpine AS builder

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

FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
    addgroup -g 1000 app && \
    adduser -D -u 1000 -G app app

COPY --from=builder /mctl-telegram /usr/local/bin/mctl-telegram
COPY --from=builder /mctl-telegram-login /usr/local/bin/mctl-telegram-login

USER app:app

EXPOSE 8080

ENTRYPOINT ["mctl-telegram"]
