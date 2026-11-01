package web

import (
	"regexp"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

// manageNav copies the shared ui_topbar navigation because the manage pages
// run under a no-script CSP and are not built from the ui templates. The two
// must list the same links in the same order, so a link added to or removed
// from the shared header cannot silently miss the manage pages.
func TestManageNavMatchesSharedTopbar(t *testing.T) {
	ui.SetAssistantsMounted(true)
	SetAssistantsMounted(true)
	t.Cleanup(func() { ui.SetAssistantsMounted(false); SetAssistantsMounted(false) })

	var shared strings.Builder
	tpl := ui.New("nav_probe", `{{template "ui_topbar" .}}`)
	if err := tpl.ExecuteTemplate(&shared, "nav_probe", ui.Data{ShowManage: true, NavActive: "manage"}); err != nil {
		t.Fatalf("render ui_topbar: %v", err)
	}
	var manage strings.Builder
	if err := newManageTemplate("nav_probe", manageNav).Execute(&manage, nil); err != nil {
		t.Fatalf("render manageNav: %v", err)
	}

	hrefs := func(html string) []string {
		i := strings.Index(html, `<nav class="site-nav"`)
		j := strings.Index(html[i:], "</nav>")
		if i < 0 || j < 0 {
			t.Fatalf("no site-nav in:\n%s", html)
		}
		var out []string
		for _, m := range regexp.MustCompile(`href="([^"]+)"`).FindAllStringSubmatch(html[i:i+j], -1) {
			out = append(out, m[1])
		}
		return out
	}
	got, want := strings.Join(hrefs(manage.String()), " "), strings.Join(hrefs(shared.String()), " ")
	if got != want {
		t.Fatalf("manage nav links = %s\nshared topbar links = %s", got, want)
	}
}
