package auth

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// attributedFailingProvider returns an AttributedError so the middleware's
// claim-logging path can be exercised without a real localjwt/sharedhmac
// round trip.
type attributedFailingProvider struct{ err error }

func (p attributedFailingProvider) Authenticate(_ *http.Request) (*Identity, error) {
	return nil, p.err
}

func captureDefaultLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestMiddleware_AuthFailedLogsClaimsOnlyWhenAttributed is T5 at the
// middleware layer: a tampered/plain failure logs no sub/client_id/jti,
// while an AttributedError (standing in for an expired-but-signed token)
// logs all four fields that are present.
func TestMiddleware_AuthFailedLogsClaimsOnlyWhenAttributed(t *testing.T) {
	t.Run("unattributed failure logs no claims", func(t *testing.T) {
		buf := captureDefaultLog(t)
		h := Middleware(attributedFailingProvider{err: errUnattributed}, true, nil, ResourceMetadata{})(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler should not run") }))
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		line := buf.String()
		for _, forbidden := range []string{"sub=", "client_id=", "jti=", "exp="} {
			if strings.Contains(line, forbidden) {
				t.Errorf("unattributed failure logged %q:\n%s", forbidden, line)
			}
		}
	})

	t.Run("attributed failure logs the present claims", func(t *testing.T) {
		buf := captureDefaultLog(t)
		attrErr := &AttributedError{
			Attr: TokenAttribution{Subject: "tg:500100101", ClientID: "acme-cli", Jti: "jti-abc", ExpiresAt: 1700000000},
			Err:  errUnattributed,
		}
		h := Middleware(attributedFailingProvider{err: attrErr}, true, nil, ResourceMetadata{})(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler should not run") }))
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		line := buf.String()
		for _, want := range []string{"sub=tg:500100101", "client_id=acme-cli", "jti=jti-abc", "exp=1700000000"} {
			if !strings.Contains(line, want) {
				t.Errorf("attributed failure log missing %q:\n%s", want, line)
			}
		}
	})

	t.Run("absent claims produce no key", func(t *testing.T) {
		buf := captureDefaultLog(t)
		attrErr := &AttributedError{Attr: TokenAttribution{Subject: "tg:1"}, Err: errUnattributed}
		h := Middleware(attributedFailingProvider{err: attrErr}, true, nil, ResourceMetadata{})(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler should not run") }))
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		line := buf.String()
		if strings.Contains(line, "client_id=") || strings.Contains(line, "jti=") || strings.Contains(line, "exp=") {
			t.Errorf("empty/zero claims must not produce a key:\n%s", line)
		}
		if !strings.Contains(line, "sub=tg:1") {
			t.Errorf("missing sub=tg:1:\n%s", line)
		}
	})
}

// errUnattributed stands in for a plain provider failure (e.g. a tampered
// signature) that never reaches AttributedError construction.
var errUnattributed = errPlain("bad token")

type errPlain string

func (e errPlain) Error() string { return string(e) }

// TestMiddleware_AuthFailedCarriesEdgeContextAndRoute is T6: edge_request_id
// and edge_route are populated from Cf-Ray/Cf-Worker when present, and fall
// back to the empty request id / "direct" route when absent.
func TestMiddleware_AuthFailedCarriesEdgeContextAndRoute(t *testing.T) {
	t.Run("edge headers present", func(t *testing.T) {
		buf := captureDefaultLog(t)
		h := Middleware(attributedFailingProvider{err: errUnattributed}, true, nil, ResourceMetadata{})(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler should not run") }))
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Cf-Ray", "abc123-DFW")
		req.Header.Set("Cf-Worker", "gateway.agents.cloudflare.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		line := buf.String()
		for _, want := range []string{"edge_request_id=abc123-DFW", "edge_route=portal"} {
			if !strings.Contains(line, want) {
				t.Errorf("missing %q:\n%s", want, line)
			}
		}
	})

	t.Run("no edge headers falls back to direct with empty request id", func(t *testing.T) {
		buf := captureDefaultLog(t)
		h := Middleware(attributedFailingProvider{err: errUnattributed}, true, nil, ResourceMetadata{})(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler should not run") }))
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		line := buf.String()
		if !strings.Contains(line, `edge_request_id=""`) {
			t.Errorf("missing empty edge_request_id:\n%s", line)
		}
		if !strings.Contains(line, "edge_route=direct") {
			t.Errorf("missing edge_route=direct:\n%s", line)
		}
	})
}
