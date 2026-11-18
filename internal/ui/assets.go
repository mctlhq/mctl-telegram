package ui

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
	"path"
	"strings"
)

// The shared-chrome pages ship their scripts as same-origin files rather than
// inline <script> blocks, so the page CSP can drop 'unsafe-inline' from
// script-src. Each file is embedded in the binary, addressed by a content-hash
// URL (/assets/<name>.<hash>.js) and served with a one-year immutable cache:
// a script change changes its URL, so nothing is ever stale and nothing needs
// purging at the Cloudflare edge.

//go:embed assets/landing.js
var landingJS string

//go:embed assets/examples.js
var examplesJS string

// AssetPrefix is the URL prefix AssetHandler must be mounted under.
const AssetPrefix = "/assets/"

type jsAsset struct {
	body string
	hash string // first 12 hex chars of sha256(body)
}

// scripts is read-only after package init.
var scripts = func() map[string]jsAsset {
	m := map[string]jsAsset{}
	for name, body := range map[string]string{
		"prepaint.js": prepaintJS,
		"toggle.js":   toggleJS,
		"landing.js":  landingJS,
		"examples.js": examplesJS,
	} {
		m[name] = jsAsset{body: body, hash: hashOf(body)}
	}
	return m
}()

// AssetURL returns the content-hashed URL of an embedded script, e.g.
// "/assets/toggle.1a2b3c4d5e6f.js". It panics on an unknown name: templates
// are parsed at startup, so a typo fails the first test run, not a request.
func AssetURL(name string) string {
	a, ok := scripts[name]
	if !ok {
		panic("ui: unknown asset " + name)
	}
	ext := path.Ext(name)
	return AssetPrefix + strings.TrimSuffix(name, ext) + "." + a.hash + ext
}

// AssetHandler serves the embedded scripts under AssetPrefix.
//
// A request whose hash matches the current build gets the immutable cache
// header. A request for a known script with another hash is a page rendered
// by the previous pod during a rolling deploy: it is answered with the current
// body but no-store, so the browser works now and nothing stale is cached
// under the old URL. Anything else is 404.
func AssetHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		file := strings.TrimPrefix(r.URL.Path, AssetPrefix)
		parts := strings.Split(file, ".")
		// <base>.<hash>.js
		if len(parts) != 3 || parts[2] != "js" || !validHash(parts[1]) {
			http.NotFound(w, r)
			return
		}
		a, ok := scripts[parts[0]+".js"]
		if !ok {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/javascript; charset=utf-8")
		if parts[1] == a.hash {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-store")
		}
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte(a.body))
	})
}

func hashOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])[:12]
}

func validHash(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
