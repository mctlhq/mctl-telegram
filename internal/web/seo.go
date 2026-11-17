package web

import (
	"encoding/xml"
	"net/http"
	"strings"
	"time"
)

type urlEntry struct {
	Loc        string  `xml:"loc"`
	LastMod    string  `xml:"lastmod,omitempty"`
	ChangeFreq string  `xml:"changefreq,omitempty"`
	Priority   float32 `xml:"priority,omitempty"`
}

type urlSet struct {
	XMLName xml.Name   `xml:"http://www.sitemaps.org/schemas/sitemap/0.9 urlset"`
	URLs    []urlEntry `xml:"url"`
}

// RobotsTxt serves robots.txt guiding search engine crawlers and referencing the sitemap.
func RobotsTxt(publicBaseURL string) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	if base == "" {
		base = "https://tg.mctl.ai"
	}
	content := "User-agent: *\n" +
		"Allow: /\n" +
		"Disallow: /api/\n" +
		"Disallow: /oauth/\n" +
		"Disallow: /telegram/connect\n" +
		"Disallow: /auth/\n" +
		"Disallow: /metrics\n" +
		"Disallow: /healthz\n" +
		"Disallow: /readyz\n\n" +
		"Sitemap: " + base + "/sitemap.xml\n"

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write([]byte(content))
	}
}

// sitemapHandler serves sitemap.xml from the public route table: every
// indexable page, with a lastmod only where the page carries a content date.
func sitemapHandler(publicBaseURL string, pages []publicPage) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	if base == "" {
		base = "https://tg.mctl.ai"
	}

	set := urlSet{
		URLs: make([]urlEntry, 0, len(pages)),
	}
	for _, p := range pages {
		if !p.Index {
			continue
		}
		e := urlEntry{
			Loc:        base + p.Path,
			ChangeFreq: p.ChangeFreq,
			Priority:   p.Priority,
		}
		if !p.LastMod.IsZero() {
			e.LastMod = p.LastMod.Format(time.DateOnly)
		}
		set.URLs = append(set.URLs, e)
	}

	data, err := xml.MarshalIndent(set, "", "  ")
	var body []byte
	if err != nil {
		body = []byte(xml.Header + "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"></urlset>")
	} else {
		body = append([]byte(xml.Header), data...)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(body)
	}
}
