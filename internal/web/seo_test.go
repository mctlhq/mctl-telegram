package web

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRobotsTxt(t *testing.T) {
	handler := RobotsTxt("https://tg.mctl.ai")
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/plain") {
		t.Errorf("expected text/plain Content-Type, got %q", contentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "User-agent: *") {
		t.Error("robots.txt must declare User-agent: *")
	}
	if !strings.Contains(body, "Allow: /") {
		t.Error("robots.txt must allow root")
	}
	if !strings.Contains(body, "Disallow: /oauth/") {
		t.Error("robots.txt must disallow /oauth/")
	}
	if !strings.Contains(body, "Disallow: /telegram/connect/") {
		t.Error("robots.txt must disallow /telegram/connect/")
	}
	if !strings.Contains(body, "Sitemap: https://tg.mctl.ai/sitemap.xml") {
		t.Error("robots.txt must reference sitemap.xml")
	}
}

func TestSitemap(t *testing.T) {
	handler := Sitemap("https://tg.mctl.ai")
	req := httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/xml") {
		t.Errorf("expected application/xml Content-Type, got %q", contentType)
	}

	var parsed urlSet
	if err := xml.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal sitemap xml: %v", err)
	}

	if len(parsed.URLs) == 0 {
		t.Fatal("sitemap must contain urls")
	}

	foundRoot := false
	foundDocs := false
	foundPrivacy := false
	for _, u := range parsed.URLs {
		if u.Loc == "https://tg.mctl.ai/" {
			foundRoot = true
		}
		if u.Loc == "https://tg.mctl.ai/docs" {
			foundDocs = true
		}
		if strings.Contains(u.Loc, "privacy") {
			foundPrivacy = true
		}
	}

	if !foundRoot {
		t.Error("sitemap must contain root https://tg.mctl.ai/")
	}
	if !foundDocs {
		t.Error("sitemap must contain https://tg.mctl.ai/docs")
	}
	if foundPrivacy {
		t.Error("sitemap must NOT contain noindex /privacy page")
	}
}
