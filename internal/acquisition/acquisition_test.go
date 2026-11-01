package acquisition

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	testKey = DeriveKey([]byte("test-secret"))
	t0      = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
)

func req(target, referer string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if referer != "" {
		r.Header.Set("Referer", referer)
	}
	return r
}

func TestCaptureWhitelistBoundsAndReferrerHost(t *testing.T) {
	long := strings.Repeat("я", 500)
	r := req("/docs?utm_source=x&utm_medium="+long+"&utm_bogus=z&utm_campaign=a%0Ab%E2%80%AEc", "https://News.Example:8443/post/1?q=2")
	s := Capture(r, "tg.example", t0)
	if s.State != StateAttributed || s.UTMSource != "x" || s.ReferrerHost != "news.example" {
		t.Fatalf("unexpected snapshot %+v", s)
	}
	if n := len([]rune(s.UTMMedium)); n != 100 {
		t.Fatalf("utm_medium runes = %d", n)
	}
	if s.UTMCampaign != "abc" {
		t.Fatalf("control/bidi not stripped: %q", s.UTMCampaign)
	}
	if s.LandingPath != "/docs" {
		t.Fatalf("landing path %q", s.LandingPath)
	}
}

func TestCaptureDirectAndSelfReferrer(t *testing.T) {
	if s := Capture(req("/", ""), "tg.example", t0); s.State != StateDirect {
		t.Fatalf("no source must be direct, got %q", s.State)
	}
	s := Capture(req("/privacy", "https://tg.example/docs"), "tg.example", t0)
	if s.State != StateDirect || s.ReferrerHost != "" {
		t.Fatalf("self referrer must count as none: %+v", s)
	}
	long := "/" + strings.Repeat("a", 400)
	if s := Capture(req(long, ""), "tg.example", t0); len(s.LandingPath) != 200 {
		t.Fatalf("path len %d", len(s.LandingPath))
	}
}

func TestEncodeDecodeRejects(t *testing.T) {
	snap := Capture(req("/?utm_source=a", ""), "h", t0)
	raw := Encode(testKey, snap)
	got, err := Decode(testKey, raw, t0.Add(time.Minute))
	if err != nil || got.UTMSource != "a" || got.State != StateAttributed {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}
	if _, err := Decode(DeriveKey([]byte("other")), raw, t0); err != ErrInvalid {
		t.Fatalf("bad MAC: %v", err)
	}
	if _, err := Decode(testKey, raw, t0.Add(TTL+time.Second)); err != ErrExpired {
		t.Fatalf("expired: %v", err)
	}
	if _, err := Decode(testKey, raw, t0.Add(-time.Hour)); err != ErrInvalid {
		t.Fatalf("future: %v", err)
	}
	for _, bad := range []string{"", "nodot", ".x", "a.b", strings.Repeat("a", 2049)} {
		if _, err := Decode(testKey, bad, t0); err != ErrInvalid {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	// A validly signed unknown state is not accepted from a cookie.
	if _, err := Decode(testKey, Encode(testKey, Snapshot{State: StateUnknown, CapturedAt: t0}), t0); err != ErrInvalid {
		t.Fatalf("unknown state in cookie: %v", err)
	}
	// Validly signed oversized values are truncated, not trusted.
	big := Snapshot{State: StateAttributed, UTMSource: strings.Repeat("z", 300), CapturedAt: t0}
	got, err = Decode(testKey, Encode(testKey, big), t0)
	if err != nil || len(got.UTMSource) != 100 {
		t.Fatalf("truncate: %d %v", len(got.UTMSource), err)
	}
}

func TestUnmarshalEmptyIsUnknown(t *testing.T) {
	if s := Unmarshal("", t0); s.State != StateUnknown {
		t.Fatalf("empty -> %q", s.State)
	}
	if s := Unmarshal("{bad", t0); s.State != StateUnknown {
		t.Fatalf("malformed -> %q", s.State)
	}
	in := Snapshot{State: StateDirect, MCPClient: "claude", CapturedAt: t0}
	if s := Unmarshal(Marshal(in), t0); s.State != StateDirect || s.MCPClient != "claude" {
		t.Fatalf("roundtrip %+v", s)
	}
}

func serve(mw func(http.Handler) http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })).ServeHTTP(rec, r)
	return rec
}

func TestMiddlewareFirstTouchWins(t *testing.T) {
	mw := Middleware(testKey, "tg.example", true, "/", "/docs")
	r := req("/?utm_source=a", "")
	r.Header.Set("Accept", "text/html")
	rec := serve(mw, r)
	cs := rec.Result().Cookies()
	if len(cs) != 1 || cs[0].Name != CookieName || !cs[0].HttpOnly || !cs[0].Secure ||
		cs[0].SameSite != http.SameSiteLaxMode || cs[0].MaxAge != 86400 || cs[0].Path != "/" {
		t.Fatalf("cookie attrs: %+v", cs)
	}
	// Second view with different UTM and the cookie: nothing is set.
	r2 := req("/docs?utm_source=b", "")
	r2.Header.Set("Accept", "text/html")
	r2.AddCookie(cs[0])
	if got := serve(mw, r2).Result().Cookies(); len(got) != 0 {
		t.Fatalf("valid cookie overwritten: %+v", got)
	}
	// A forged cookie is replaced.
	r3 := req("/docs?utm_source=c", "")
	r3.Header.Set("Accept", "text/html")
	r3.AddCookie(&http.Cookie{Name: CookieName, Value: "x.y"})
	if got := serve(mw, r3).Result().Cookies(); len(got) != 1 {
		t.Fatalf("forged cookie not replaced")
	}
}

func TestMiddlewareScope(t *testing.T) {
	mw := Middleware(testKey, "tg.example", false, "/")
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/"}, {http.MethodGet, "/oauth/authorize"}, {http.MethodGet, "/telegram/connect"},
		{http.MethodGet, "/local-bridge/activate"},
	} {
		r := httptest.NewRequest(c.method, c.path, nil)
		r.Header.Set("Accept", "text/html")
		if got := serve(mw, r).Result().Cookies(); len(got) != 0 {
			t.Fatalf("%s %s set a cookie", c.method, c.path)
		}
	}
	// An MCP client (event-stream) on "/" gets none.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept", "text/event-stream")
	if got := serve(mw, r).Result().Cookies(); len(got) != 0 {
		t.Fatal("event-stream request set a cookie")
	}
}
