package mcpprobe

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// Mode selects which protocol path a run exercises. The two are deliberately
// separate: they negotiate differently, they carry different headers, and
// conflating their results is how a server gets described as modern on the
// strength of a legacy handshake.
type Mode string

const (
	// ModeModern drives the stateless 2026-07-28 path: server/discover first,
	// per-request metadata, no session identifier.
	ModeModern Mode = "modern"
	// ModeLegacy drives the 2025-era initialize/session lifecycle.
	ModeLegacy Mode = "legacy"
)

// Source records where a report's evidence came from. A result produced by an
// in-process test server says so and can never be presented as a measurement
// of a deployed endpoint.
type Source string

const (
	// SourceInProcess is an httptest server around the real handler wiring.
	// This is all continuous integration can produce.
	SourceInProcess Source = "in-process-current-main"
	// SourceDirect is an operator run against a deployed endpoint.
	SourceDirect Source = "direct-deployed"
	// SourceGateway is an operator run through an enterprise MCP gateway.
	SourceGateway Source = "cloudflare-portal"
)

// DefaultTool is the probe's preferred call target: a read-only status
// capability that returns no message content, no peer and no chat title.
const DefaultTool = "get_my_send_status"

// defaultTimeout bounds a single HTTP request. A probe that hangs is a probe
// nobody runs in a pipeline.
const defaultTimeout = 15 * time.Second

// legacyVersions are the pre-2026-07-28 protocol versions a legacy run may
// select. The value is explicit rather than negotiated so the report can name
// what was asked for alongside what the server answered.
var legacyVersions = []string{
	mcp.ProtocolVersion20251125,
	mcp.ProtocolVersion20250618,
	mcp.ProtocolVersion20250326,
	mcp.ProtocolVersion20241105,
}

// Options configure a single run. The zero value is not usable; call Run,
// which validates.
type Options struct {
	// URL is the MCP endpoint, including its path.
	URL string
	// Mode selects the protocol path. Required — there is no default, so a
	// caller cannot get a legacy measurement while believing it asked for a
	// modern one.
	Mode Mode
	// LegacyVersion is the protocol version a legacy run offers at
	// initialize. Required for ModeLegacy, rejected for ModeModern.
	LegacyVersion string
	// Token is the bearer credential. It is used to build the Authorization
	// header and is never copied into the report.
	Token string
	// Tool names the read-only capability to invoke. Empty means DefaultTool.
	Tool string
	// Source labels the evidence. Empty means SourceDirect.
	Source Source
	// GitRef records the build under test, when the caller knows it.
	GitRef string
	// SkipOAuth omits the discovery/challenge probe, for a target whose
	// authorization surface is out of scope for the run.
	SkipOAuth bool
	// HTTPClient overrides the default client. Redirects are not followed by
	// the default: a redirected probe measures a different endpoint than the
	// one it was pointed at.
	HTTPClient *http.Client
	// Now overrides the clock, for tests.
	Now func() time.Time
}

func (o *Options) normalize() error {
	if strings.TrimSpace(o.URL) == "" {
		return errors.New("URL is required")
	}
	u, err := url.Parse(o.URL)
	if err != nil {
		return fmt.Errorf("URL %q is not a valid URL: %w", o.URL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme %q is not supported (want http or https)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("URL %q has no host", o.URL)
	}
	switch o.Mode {
	case ModeModern:
		if o.LegacyVersion != "" {
			return errors.New("LegacyVersion is meaningless in modern mode")
		}
	case ModeLegacy:
		if o.LegacyVersion == "" {
			return errors.New("LegacyVersion is required in legacy mode")
		}
		if !isLegacyVersion(o.LegacyVersion) {
			return fmt.Errorf("LegacyVersion %q is not a supported legacy protocol version (want one of %s)",
				o.LegacyVersion, strings.Join(legacyVersions, ", "))
		}
	case "":
		return errors.New("Mode is required (modern or legacy)")
	default:
		return fmt.Errorf("unknown Mode %q", o.Mode)
	}
	switch o.Source {
	case "":
		o.Source = SourceDirect
	case SourceInProcess, SourceDirect, SourceGateway:
	default:
		return fmt.Errorf("unknown Source %q", o.Source)
	}
	if o.Tool == "" {
		o.Tool = DefaultTool
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{
			Timeout: defaultTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return nil
}

func isLegacyVersion(v string) bool {
	for _, known := range legacyVersions {
		if v == known {
			return true
		}
	}
	return false
}

// protocolVersion is the version a run declares on the wire.
func (o *Options) protocolVersion() string {
	if o.Mode == ModeModern {
		return mcp.ProtocolVersion20260728
	}
	return o.LegacyVersion
}
