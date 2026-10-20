package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testPlatformFacts() PlatformFacts {
	return PlatformFacts{
		AllowSend:        true,
		RateLimitPerUser: 30,
		PeerSendCap:      20,
		PeerWindow:       time.Hour,
		AccessTokenTTL:   time.Hour,
		RefreshTokenTTL:  720 * time.Hour,
		MediaMaxBytes:    20 << 20,
	}
}

func renderPlatforms(t *testing.T, f PlatformFacts) string {
	t.Helper()
	w := httptest.NewRecorder()
	Platforms("https://tg.example.test/", "mcp", "", true, f).ServeHTTP(w, httptest.NewRequest("GET", "/platforms", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html, got %q", ct)
	}
	return w.Body.String()
}

func TestPlatforms_ServesHTML(t *testing.T) {
	body := renderPlatforms(t, testPlatformFacts())
	for _, must := range []string{
		"https://tg.example.test/mcp",
		"https://tg.example.test/.well-known/oauth-protected-resource",
		"https://tg.example.test/.well-known/oauth-authorization-server",
		"Client ID Metadata Document",
		"Dynamic Client Registration",
		"telegram:messages:send",
		"account:manage",
		"Every account starts read-only.",
		"Local Bridge",
		"issues/781",
		`<link rel="canonical" href="https://tg.example.test/platforms">`,
		`<a href="/platforms" class="active">platforms</a>`,
		`class="table-scroll"`,
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/platforms missing %q", must)
		}
	}
}

// The limits table quotes the running configuration, not fixed text.
func TestPlatforms_LimitsComeFromConfig(t *testing.T) {
	f := testPlatformFacts()
	f.RateLimitPerUser = 45
	f.AccessTokenTTL = 2 * time.Hour
	f.RefreshTokenTTL = 7 * 24 * time.Hour
	f.MediaMaxBytes = 5 << 20
	body := renderPlatforms(t, f)
	for _, must := range []string{
		"45 per minute",
		"20 per 1 hour",
		"2 hours",
		"7 days, rotated on every use",
		"5 MiB per file",
		"(it does on this deployment)",
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/platforms missing %q", must)
		}
	}

	f.AllowSend = false
	if body := renderPlatforms(t, f); !strings.Contains(body, "(it does not on this deployment)") {
		t.Fatal("/platforms must say sending is off when ALLOW_SEND is off")
	}
}

func TestPlatforms_CIMDStatusFollowsConfig(t *testing.T) {
	cases := []struct {
		accept, advertise bool
		want, notWant     string
	}{
		{false, false, "CIMD is not enabled.", "CIMD is accepted for approved hosts."},
		{true, false, "Discovery does not advertise it yet", "Discovery advertises it"},
		{true, true, "Discovery advertises it", "Discovery does not advertise it yet"},
	}
	for _, c := range cases {
		f := testPlatformFacts()
		f.CIMDAccept, f.CIMDAdvertise = c.accept, c.advertise
		body := renderPlatforms(t, f)
		if !strings.Contains(body, c.want) || strings.Contains(body, c.notWant) {
			t.Errorf("accept=%v advertise=%v: want %q and not %q", c.accept, c.advertise, c.want, c.notWant)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                "not set",
		time.Minute:      "1 minute",
		10 * time.Minute: "10 minutes",
		time.Hour:        "1 hour",
		720 * time.Hour:  "30 days",
		90 * time.Second: "1m30s",
	} {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "no cap", 20 << 20: "20 MiB", 64 << 10: "64 KiB", 1000: "1000 bytes"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
