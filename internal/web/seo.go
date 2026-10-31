package web

import (
	"encoding/xml"
	"net/http"
	"strings"
)

type urlEntry struct {
	Loc        string  `xml:"loc"`
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

// Sitemap serves sitemap.xml listing public, indexed pages.
func Sitemap(publicBaseURL string) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	if base == "" {
		base = "https://tg.mctl.ai"
	}

	routes := []struct {
		path       string
		changefreq string
		priority   float32
	}{
		{"/", "weekly", 1.0},
		{"/docs", "weekly", 0.8},
		{"/platforms", "weekly", 0.8},
		{"/demo", "monthly", 0.7},
		{"/security", "monthly", 0.5},
		{"/docs/local-bridge", "monthly", 0.6},
		{"/docs/product-updates", "weekly", 0.7},
	}

	set := urlSet{
		URLs: make([]urlEntry, 0, len(routes)),
	}
	for _, rt := range routes {
		loc := base + rt.path
		set.URLs = append(set.URLs, urlEntry{
			Loc:        loc,
			ChangeFreq: rt.changefreq,
			Priority:   rt.priority,
		})
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
