package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClassifyDemoVideo(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantKind  string
		wantEmbed string
	}{
		{"empty", "", demoVideoNone, ""},
		{"blank", "   ", demoVideoNone, ""},
		{"garbage", "not a url", demoVideoNone, ""},
		{"non-http scheme", "ftp://example.com/x", demoVideoNone, ""},
		{"youtube watch", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", demoVideoYouTube, "https://www.youtube.com/embed/dQw4w9WgXcQ"},
		{"youtube watch extra params", "https://youtube.com/watch?v=abc123&t=42", demoVideoYouTube, "https://www.youtube.com/embed/abc123"},
		{"youtu.be short", "https://youtu.be/dQw4w9WgXcQ", demoVideoYouTube, "https://www.youtube.com/embed/dQw4w9WgXcQ"},
		{"youtube embed already", "https://www.youtube.com/embed/xyz789", demoVideoYouTube, "https://www.youtube.com/embed/xyz789"},
		{"loom share", "https://www.loom.com/share/abc123def", demoVideoLoom, "https://www.loom.com/embed/abc123def"},
		{"loom embed already", "https://loom.com/embed/abc123def", demoVideoLoom, "https://www.loom.com/embed/abc123def"},
		{"mp4 file", "https://tg.mctl.ai/demo.mp4", demoVideoFile, "https://tg.mctl.ai/demo.mp4"},
		{"webm file", "https://cdn.example.com/clip.webm", demoVideoFile, "https://cdn.example.com/clip.webm"},
		{"unknown host links out", "https://vimeo.com/123456", demoVideoLink, "https://vimeo.com/123456"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, embed := classifyDemoVideo(tc.in)
			if kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", kind, tc.wantKind)
			}
			if embed != tc.wantEmbed {
				t.Errorf("embed = %q, want %q", embed, tc.wantEmbed)
			}
		})
	}
}

func TestDemo_Placeholder(t *testing.T) {
	w := httptest.NewRecorder()
	Demo("https://tg.mctl.ai", "").ServeHTTP(w, httptest.NewRequest("GET", "/demo", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Demo video coming soon") {
		t.Error("placeholder page missing 'Demo video coming soon'")
	}
	if strings.Contains(body, "<iframe") {
		t.Error("placeholder page should not render an iframe")
	}
}

func TestDemoWalkthrough(t *testing.T) {
	w := httptest.NewRecorder()
	DemoWalkthrough().ServeHTTP(w, httptest.NewRequest("GET", "/demo/walkthrough.mp4", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "video/mp4" {
		t.Errorf("Content-Type = %q, want video/mp4", ct)
	}
	if w.Body.Len() == 0 {
		t.Error("expected non-empty video body")
	}
}

func TestDemo_YouTubeEmbed(t *testing.T) {
	w := httptest.NewRecorder()
	Demo("https://tg.mctl.ai", "https://youtu.be/dQw4w9WgXcQ").ServeHTTP(w, httptest.NewRequest("GET", "/demo", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "https://www.youtube.com/embed/dQw4w9WgXcQ") {
		t.Error("youtube page missing the /embed/ iframe src")
	}
	if !strings.Contains(body, "<iframe") {
		t.Error("youtube page should render an iframe")
	}
}
