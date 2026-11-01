package audit

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// The OpenAI-compatible runner's credentials are registered in
// sensitiveKeys in redact.go. Dropping an entry must turn this red.
func TestRedaction_OpenAIRunnerCredentials(t *testing.T) {
	const secret = "sk-test-do-not-log"
	for _, key := range []string{"AGENT_OPENAI_API_KEY", "agent_gateway_token", "cf-aig-authorization"} {
		t.Run(key, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))
			log.LogAttrs(context.Background(), slog.LevelInfo, "cfg",
				slog.String(key, secret),
				slog.Group("nested", slog.String(key, secret)))
			if strings.Contains(buf.String(), secret) {
				t.Fatalf("key %q leaked into log output: %s", key, buf.String())
			}
		})
	}
}
