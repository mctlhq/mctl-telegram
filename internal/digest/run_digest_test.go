package digest

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// capturingRoundTripper records every request body it sees and always
// answers 200 OK, so runDigest's send path succeeds without a network call.
type capturingRoundTripper struct {
	bodies []string
}

func (c *capturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		c.bodies = append(c.bodies, string(b))
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"ok":true,"result":{"message_id":1}}`)),
		Header:     make(http.Header),
	}, nil
}

// TestRunDigest_ConnectStepLookupFailureDegradesGracefully is T7: when
// LastConnectStepFor errors, runDigest must still send the digest, with
// every "no session" row rendering the plain pre-existing text (never a
// dangling "last:" suffix), and it must log a warning rather than fail
// silently or abort the send.
func TestRunDigest_ConnectStepLookupFailureDegradesGracefully(t *testing.T) {
	ctx := context.Background()
	store := newDigestTestStore(t)

	// A fresh user with no session — this is the row whose suffix we assert
	// on. CreatedAt defaults to CURRENT_TIMESTAMP, so it always falls inside
	// runDigest's 24h lookback window.
	if _, err := store.EnsureUserByTelegramID(ctx, 700100201, "grace_tg", "Grace"); err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	// Break LastConnectStepFor specifically (it queries audit_logs) while
	// leaving ListIdentities — which never touches audit_logs — working.
	if _, err := store.DB.ExecContext(ctx, `DROP TABLE audit_logs`); err != nil {
		t.Fatalf("drop audit_logs: %v", err)
	}

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rt := &capturingRoundTripper{}
	withStubTransport(t, rt)

	runDigest(ctx, store, "test-token", []int64{999}, false)

	if !strings.Contains(buf.String(), "digest: last connect step") {
		t.Errorf("expected a warning naming the failed lookup; log:\n%s", buf.String())
	}

	if len(rt.bodies) == 0 {
		t.Fatal("expected the digest to still be sent despite the lookup failure")
	}
	form, err := url.ParseQuery(rt.bodies[0])
	if err != nil {
		t.Fatalf("parse sent form body: %v", err)
	}
	sent := form.Get("text")
	if !strings.Contains(sent, "no session") {
		t.Errorf("sent digest missing the plain no-session text; body:\n%s", sent)
	}
	if strings.Contains(sent, "no session — last:") {
		t.Errorf("sent digest must degrade to the plain text, not the annotated suffix; body:\n%s", sent)
	}
}
