// Package acquisition records how a visitor first found the service: the
// whitelisted UTM keys, the referring host, the landing path and the MCP
// client. The first public content page a human lands on mints a signed
// first-party cookie; /oauth/authorize turns it into a Snapshot carried with
// the pending-auth entry; the snapshot is persisted once, when the users row
// is created.
//
// Three outcomes are kept apart and never inferred from one another:
// attributed (a UTM value or an external referrer was observed), direct
// (capture ran and observed neither) and unknown (no usable capture).
//
// Only coarse data is held: no IP address, no user agent, no referrer path.
package acquisition

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/hkdf"
)

// Snapshot states.
const (
	StateAttributed = "attributed"
	StateDirect     = "direct"
	StateUnknown    = "unknown"
)

const (
	// CookieName is the first-party acquisition cookie.
	CookieName = "mctl_acq"
	// TTL is the cookie lifetime and the maximum accepted age on decode.
	TTL = 24 * time.Hour

	maxCookieBytes = 2048
	maxUTMRunes    = 100
	maxPathRunes   = 200
	maxHostBytes   = 253
	maxClientRunes = 40
	futureSkew     = 5 * time.Minute

	keyInfo = "mctl-telegram/acquisition-cookie/v1"
)

// Decode failure classes, used as metric reasons.
var (
	ErrInvalid = errors.New("acquisition: invalid cookie")
	ErrExpired = errors.New("acquisition: expired cookie")
)

// Snapshot is the acquisition record for one sign-up.
type Snapshot struct {
	State        string    `json:"s"`
	UTMSource    string    `json:"us,omitempty"`
	UTMMedium    string    `json:"um,omitempty"`
	UTMCampaign  string    `json:"uc,omitempty"`
	UTMContent   string    `json:"ut,omitempty"`
	UTMTerm      string    `json:"ue,omitempty"`
	ReferrerHost string    `json:"rh,omitempty"`
	LandingPath  string    `json:"lp,omitempty"`
	MCPClient    string    `json:"mc,omitempty"`
	CapturedAt   time.Time `json:"t"`
}

// DeriveKey derives the cookie MAC key from the OAuth JWT secret with a
// dedicated HKDF info label, so the raw secret is never used for MACs here.
func DeriveKey(jwtSecret []byte) []byte {
	r := hkdf.New(sha256.New, jwtSecret, nil, []byte(keyInfo))
	key := make([]byte, 32)
	_, _ = io.ReadFull(r, key)
	return key
}

func isBidi(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return r == 0x200E || r == 0x200F || r == 0x061C
}

// Clean strips control characters, line separators and bidi overrides, trims
// space and truncates to max runes.
func Clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || isBidi(r) || r == 0x2028 || r == 0x2029 || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

// Capture observes a first page view. selfHost is the service's own public
// host (no port); a referrer from it counts as no referrer.
func Capture(r *http.Request, selfHost string, now time.Time) Snapshot {
	q := r.URL.Query()
	snap := Snapshot{
		UTMSource:   Clean(q.Get("utm_source"), maxUTMRunes),
		UTMMedium:   Clean(q.Get("utm_medium"), maxUTMRunes),
		UTMCampaign: Clean(q.Get("utm_campaign"), maxUTMRunes),
		UTMContent:  Clean(q.Get("utm_content"), maxUTMRunes),
		UTMTerm:     Clean(q.Get("utm_term"), maxUTMRunes),
		LandingPath: Clean(r.URL.Path, maxPathRunes),
		CapturedAt:  now.UTC(),
	}
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			h := strings.ToLower(u.Hostname())
			if h != "" && len(h) <= maxHostBytes && h != strings.ToLower(selfHost) {
				snap.ReferrerHost = Clean(h, maxHostBytes)
			}
		}
	}
	snap.State = StateDirect
	if snap.hasSource() {
		snap.State = StateAttributed
	}
	return snap
}

func (s Snapshot) hasSource() bool {
	return s.UTMSource != "" || s.UTMMedium != "" || s.UTMCampaign != "" ||
		s.UTMContent != "" || s.UTMTerm != "" || s.ReferrerHost != ""
}

// Unknown returns the snapshot for a sign-up with no usable capture.
func Unknown(mcpClient string, now time.Time) Snapshot {
	return Snapshot{State: StateUnknown, MCPClient: Clean(mcpClient, maxClientRunes), CapturedAt: now.UTC()}
}

func sign(key []byte, payload string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Encode serialises and signs a snapshot for the cookie.
func Encode(key []byte, s Snapshot) string {
	b, _ := json.Marshal(s)
	p := base64.RawURLEncoding.EncodeToString(b)
	return p + "." + sign(key, p)
}

// Decode verifies and parses a cookie value. Every field is re-cleaned, so a
// validly signed cookie minted with longer values is truncated, not trusted.
func Decode(key []byte, raw string, now time.Time) (Snapshot, error) {
	var s Snapshot
	if raw == "" || len(raw) > maxCookieBytes {
		return s, ErrInvalid
	}
	p, mac, ok := strings.Cut(raw, ".")
	if !ok || p == "" {
		return s, ErrInvalid
	}
	if !hmac.Equal([]byte(mac), []byte(sign(key, p))) {
		return s, ErrInvalid
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return s, ErrInvalid
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return Snapshot{}, ErrInvalid
	}
	if s.State != StateAttributed && s.State != StateDirect {
		return Snapshot{}, ErrInvalid
	}
	if now.Sub(s.CapturedAt) > TTL {
		return Snapshot{}, ErrExpired
	}
	if s.CapturedAt.Sub(now) > futureSkew {
		return Snapshot{}, ErrInvalid
	}
	s.Normalize()
	return s, nil
}

// Normalize re-applies the bounds to every field and recomputes the state
// between attributed and direct from the cleaned values.
func (s *Snapshot) Normalize() {
	s.UTMSource = Clean(s.UTMSource, maxUTMRunes)
	s.UTMMedium = Clean(s.UTMMedium, maxUTMRunes)
	s.UTMCampaign = Clean(s.UTMCampaign, maxUTMRunes)
	s.UTMContent = Clean(s.UTMContent, maxUTMRunes)
	s.UTMTerm = Clean(s.UTMTerm, maxUTMRunes)
	s.ReferrerHost = Clean(strings.ToLower(s.ReferrerHost), maxHostBytes)
	s.LandingPath = Clean(s.LandingPath, maxPathRunes)
	s.MCPClient = Clean(s.MCPClient, maxClientRunes)
	if s.State == StateAttributed && !s.hasSource() {
		s.State = StateDirect
	}
}

// Marshal serialises a snapshot (unsigned) for the pending-auth entry.
func Marshal(s Snapshot) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Unmarshal parses a stored snapshot. An empty or malformed value, for
// example a pending row minted by an older image, yields state unknown.
func Unmarshal(raw string, now time.Time) Snapshot {
	if raw == "" || len(raw) > maxCookieBytes {
		return Unknown("", now)
	}
	var s Snapshot
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return Unknown("", now)
	}
	switch s.State {
	case StateAttributed, StateDirect, StateUnknown:
	default:
		return Unknown("", now)
	}
	s.Normalize()
	return s
}

// Middleware sets the acquisition cookie on the first browser GET of one of
// the given exact public content paths. A valid cookie is never overwritten
// (first touch wins); an invalid or expired one is replaced.
func Middleware(key []byte, selfHost string, secure bool, paths ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(paths))
	for _, p := range paths {
		allowed[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && allowed[r.URL.Path] &&
				strings.Contains(r.Header.Get("Accept"), "text/html") {
				now := time.Now()
				c, err := r.Cookie(CookieName)
				valid := false
				if err == nil {
					_, derr := Decode(key, c.Value, now)
					valid = derr == nil
				}
				if !valid {
					http.SetCookie(w, &http.Cookie{
						Name:     CookieName,
						Value:    Encode(key, Capture(r, selfHost, now)),
						Path:     "/",
						MaxAge:   int(TTL / time.Second),
						HttpOnly: true,
						Secure:   secure,
						SameSite: http.SameSiteLaxMode,
					})
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
