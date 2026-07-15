package web

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

//go:embed demo.html
var demoHTML string

//go:embed walkthrough.mp4
var demoWalkthroughMP4 []byte

var demoTmpl = ui.New("demo", demoHTML)

// demoWalkthroughModTime is a fixed timestamp so http.ServeContent can emit a
// stable Last-Modified / conditional-request response for the embedded video.
var demoWalkthroughModTime = time.Date(2026, time.June, 5, 18, 30, 0, 0, time.UTC)

// DemoWalkthrough serves the embedded screen-recorded walkthrough as an mp4 at
// /demo/walkthrough.mp4. Anonymous-accessible like the /demo page itself.
// http.ServeContent handles range requests, Content-Length, and conditional
// GETs; the Content-Type is fixed to video/mp4 and the response is cached
// aggressively since the bytes are baked into the binary.
func DemoWalkthrough() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeContent(w, r, "walkthrough.mp4", demoWalkthroughModTime, bytes.NewReader(demoWalkthroughMP4))
	}
}

// Video-kind discriminators rendered by demo.html. "none" shows the
// placeholder; the others select an iframe / <video> / plain link.
const (
	demoVideoNone    = "none"
	demoVideoYouTube = "youtube"
	demoVideoLoom    = "loom"
	demoVideoFile    = "file"
	demoVideoLink    = "link"
)

// demoData embeds the shared chrome data and adds the resolved video fields.
// EmbedURL is template.URL so html/template permits it as an iframe/<video>
// src — it is only ever a URL this package constructed from a recognised host,
// never the raw operator-supplied string interpolated into an attribute.
type demoData struct {
	ui.Data
	VideoKind string
	EmbedURL  template.URL
	RawURL    string
}

// Demo serves the public review walkthrough page at /demo. Anonymous-accessible
// like Privacy/Security/Terms — there is nothing user-specific here. The video
// source comes from DEMO_VIDEO_URL; empty renders a "coming soon" placeholder.
func Demo(publicBaseURL, demoVideoURL string, showManage bool) http.HandlerFunc {
	kind, embed := classifyDemoVideo(demoVideoURL)
	data := demoData{
		Data: ui.Data{
			Title:         "MCTL Telegram Demo",
			NavActive:     "demo",
			PublicBaseURL: strings.TrimRight(publicBaseURL, "/"),
			ShowManage:    showManage,
		},
		VideoKind: kind,
		EmbedURL:  template.URL(embed),
		RawURL:    strings.TrimSpace(demoVideoURL),
	}
	return chromePage(demoTmpl, "demo", data)
}

// classifyDemoVideo maps a configured video URL to a render kind and, where an
// embed is possible, a safe player URL built from the parsed components:
//
//   - empty / unparseable / non-http(s)        → "none" (placeholder)
//   - youtube.com/watch?v=ID or youtu.be/ID    → "youtube", /embed/ID
//   - loom.com/share/ID (or /embed/ID)         → "loom", /embed/ID
//   - path ends .mp4/.webm                      → "file" (native <video>)
//   - any other valid http(s) URL              → "link" (plain anchor)
//
// The embed URL is reconstructed from a fixed host + the extracted id, so a
// crafted DEMO_VIDEO_URL cannot smuggle a different origin into the iframe.
func classifyDemoVideo(raw string) (kind, embed string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return demoVideoNone, ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return demoVideoNone, ""
	}

	host := strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
	path := strings.Trim(u.Path, "/")

	switch {
	case host == "youtu.be":
		if id := firstPathSegment(path); id != "" {
			return demoVideoYouTube, "https://www.youtube.com/embed/" + id
		}
	case host == "youtube.com" || host == "m.youtube.com":
		if strings.HasPrefix(path, "embed/") {
			if id := firstPathSegment(strings.TrimPrefix(path, "embed/")); id != "" {
				return demoVideoYouTube, "https://www.youtube.com/embed/" + id
			}
		}
		if id := u.Query().Get("v"); id != "" {
			return demoVideoYouTube, "https://www.youtube.com/embed/" + id
		}
	case host == "loom.com":
		// /share/<id> and /embed/<id> both carry the id in the second segment.
		segs := strings.Split(path, "/")
		if len(segs) >= 2 && (segs[0] == "share" || segs[0] == "embed") && segs[1] != "" {
			return demoVideoLoom, "https://www.loom.com/embed/" + segs[1]
		}
	}

	lp := strings.ToLower(u.Path)
	if strings.HasSuffix(lp, ".mp4") || strings.HasSuffix(lp, ".webm") {
		return demoVideoFile, raw
	}

	// Recognised scheme/host but not an embeddable provider: link out rather
	// than iframe an unknown origin.
	return demoVideoLink, raw
}

// firstPathSegment returns the first non-empty segment of a slash-trimmed path.
func firstPathSegment(p string) string {
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return p
}
