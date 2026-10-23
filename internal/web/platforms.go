package web

import (
	_ "embed"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

//go:embed platforms.html
var platformsHTML string

var platformsTmpl = ui.New("platforms", platformsHTML)

// PlatformFacts are the deployment values /platforms quotes. They come from
// the running config rather than from the page text, so the page cannot
// promise a limit or a CIMD status the deployment does not have.
type PlatformFacts struct {
	AllowSend          bool
	CIMDAccept         bool
	CIMDAdvertise      bool
	RateLimitPerUser   int
	RegisterRatePerMin int
	PeerSendCap        int
	PeerCleanupCap     int
	PeerWindow         time.Duration
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	MediaMaxBytes      int64
	MediaUploadBytes   int64
	BulkMediaBytes     int64
}

type platformsData struct {
	ui.Data
	MCPURL       string
	WellKnownURL string
	AuthServer   string
	PlatformFacts
	AccessTTL   string
	RefreshTTL  string
	PeerWin     string
	MediaMax    string
	MediaUpload string
	BulkMedia   string
}

// Platforms renders /platforms, the integration guide for agent platforms
// and MCP gateways that connect many users. Anonymous-accessible, like
// /security: it describes the deployment, not a user.
func Platforms(publicBaseURL, mcpPath, authServer string, showManage bool, f PlatformFacts) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	mcpPath = "/" + strings.TrimLeft(mcpPath, "/")
	if authServer == "" {
		authServer = base
	}
	return chromePage(platformsTmpl, "platforms", platformsData{
		Data: ui.Data{
			Title:         "MCTL — for agent platforms",
			Description:   "How an agent platform or MCP gateway connects its users to MCTL: OAuth with DCR or Client ID Metadata Documents, scopes, limits, reliability targets and revocation.",
			NavActive:     "platforms",
			PublicBaseURL: base,
			ShowManage:    showManage,
			CanonicalPath: "/platforms",
		},
		MCPURL:        base + mcpPath,
		WellKnownURL:  base + "/.well-known/oauth-protected-resource",
		AuthServer:    strings.TrimRight(authServer, "/"),
		PlatformFacts: f,
		AccessTTL:     humanDuration(f.AccessTokenTTL),
		RefreshTTL:    humanDuration(f.RefreshTokenTTL),
		PeerWin:       perWindow(f.PeerWindow),
		MediaMax:      humanBytes(f.MediaMaxBytes),
		MediaUpload:   humanBytes(f.MediaUploadBytes),
		BulkMedia:     humanBytes(f.BulkMediaBytes),
	})
}

// humanDuration renders whole days, hours or minutes, falling back to Go's
// own format for anything that is not a whole unit.
func humanDuration(d time.Duration) string {
	plural := func(n int64, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d <= 0:
		return "not set"
	case d%(24*time.Hour) == 0:
		return plural(int64(d/(24*time.Hour)), "day")
	case d%time.Hour == 0:
		return plural(int64(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return plural(int64(d/time.Minute), "minute")
	}
	return d.String()
}

// perWindow renders a window after "per": "hour" rather than "1 hour",
// "6 hours" when the count is not one.
func perWindow(d time.Duration) string {
	return strings.TrimPrefix(humanDuration(d), "1 ")
}

func humanBytes(n int64) string {
	switch {
	case n <= 0:
		return "no cap"
	case n%1_000_000 == 0:
		// Decimal caps such as the 12 MB media limit (12000000) are set in
		// SI units. Checked before the binary cases: 16000000 is also a
		// multiple of 1024 and would otherwise render as "15625 KiB". No
		// power-of-two cap is a multiple of 10^6, so those are unaffected.
		return fmt.Sprintf("%d MB", n/1_000_000)
	case n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}
