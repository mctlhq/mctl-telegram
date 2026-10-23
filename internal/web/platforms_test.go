package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testPlatformFacts() PlatformFacts {
	return PlatformFacts{
		AllowSend:          true,
		RateLimitPerUser:   30,
		RegisterRatePerMin: 10,
		MediaUploadBytes:   20 << 20,
		BulkMediaBytes:     8 << 20,
		PeerSendCap:        20,
		PeerWindow:         time.Hour,
		AccessTokenTTL:     time.Hour,
		RefreshTokenTTL:    720 * time.Hour,
		MediaMaxBytes:      20 << 20,
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
		"The tool list follows the grant.",
		"request it if users should be able to leave from inside your platform",
		"Local Bridge",
		"every client's refresh tokens for that user, every worker token issued for the user's Telegram id, and every Local Bridge device",
		"only if your client calls <code>/oauth/revoke</code>",
		`<link rel="canonical" href="https://tg.example.test/platforms">`,
		`<a href="/platforms" class="active">platforms</a>`,
		// footer twin of the topbar entry
		`<span class="sep">·</span>
      <a href="/platforms">platforms</a>`,
		`class="table-scroll"`,
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/platforms missing %q", must)
		}
	}
	// Account deletion revokes OAuth grants since #781; the page must not
	// still describe that as a gap.
	for _, gone := range []string{"Known gap", "issues/781"} {
		if strings.Contains(body, gone) {
			t.Fatalf("/platforms still contains %q", gone)
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
	f.RegisterRatePerMin = 7
	f.MediaUploadBytes = 3 << 20
	f.BulkMediaBytes = 6 << 20
	body := renderPlatforms(t, f)
	for _, must := range []string{
		"45 per minute",
		"20 per hour",
		"7 attempts per minute",
		"3 MiB per file",
		"6 MiB in total",
		"omits <code>scope</code> gets the user's full entitled set",
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

func TestPerWindow(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Hour: "hour", 6 * time.Hour: "6 hours", 24 * time.Hour: "day"} {
		if got := perWindow(d); got != want {
			t.Errorf("perWindow(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "no cap", 20 << 20: "20 MiB", 64 << 10: "64 KiB", 12_000_000: "12 MB", 16_000_000: "16 MB", 1000: "1000 bytes"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// The manage page is mounted only in local-jwt mode, so a deployment without
// it must not send integrators there.
func TestPlatforms_ManagePageOnlyWhenMounted(t *testing.T) {
	render := func(showManage bool) string {
		w := httptest.NewRecorder()
		Platforms("https://tg.example.test/", "mcp", "", showManage, testPlatformFacts()).ServeHTTP(w, httptest.NewRequest("GET", "/platforms", nil))
		return w.Body.String()
	}
	if body := render(true); !strings.Contains(body, "A user can disconnect their Telegram session on <code>/telegram/connect/manage</code>.") {
		t.Fatal("with the manage page mounted, /platforms must point users at it")
	}
	if body := render(false); strings.Contains(body, "/telegram/connect/manage") {
		t.Fatal("without the manage page, /platforms must not link to it")
	}
}
