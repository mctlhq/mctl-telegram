package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
)

const (
	testSHA  = "0123456789abcdef0123456789abcdef01234567"
	digestA  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestB  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	notFound = `{"error":"assistant version not found","code":"assistant_not_found"}`
)

func entry(name, version, digest string) *assistant.Entry {
	def := &assistant.Definition{}
	def.Metadata.Name, def.Metadata.Version = name, version
	def.Metadata.Visibility, def.Metadata.Status = "public", "active"
	return &assistant.Entry{
		Definition:   def,
		Materialized: []byte(`{"kind":"TelegramAssistant"}`),
		Digest:       digest,
		Source:       "assistants/" + name + "/versions/" + version + "/assistant.yaml",
	}
}

func catalogBody(name, version, lifecycle, digest string) string {
	b, _ := json.Marshal(map[string]any{
		"name": name, "version": version, "title": "Recruiter assistant",
		"lifecycle": lifecycle, "digest": digest, "variables": []any{}, "intents": []any{},
	})
	return string(b)
}

type reply struct {
	status int
	body   string
}

// registry answers the per-version catalog route from a fixture keyed by
// "name@version" and counts the requests it served.
func registry(t *testing.T, fixture map[string]reply) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/assistant-catalog/")
		parts := strings.Split(rest, "/")
		if !ok || len(parts) != 3 || parts[1] != "versions" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusTeapot)
			return
		}
		rep, ok := fixture[parts[0]+"@"+parts[2]]
		if !ok {
			t.Errorf("unexpected lookup %s", r.URL.Path)
			http.Error(w, "unexpected", http.StatusTeapot)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rep.status)
		_, _ = w.Write([]byte(rep.body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUnpublishedVersionGetsACommandAndABody(t *testing.T) {
	srv, _ := registry(t, map[string]reply{
		"hr-recruiter@0.1.0": {200, catalogBody("hr-recruiter", "0.1.0", "published", digestA)},
		"hr-recruiter@0.1.1": {404, notFound},
	})
	out := t.TempDir()
	entries := []*assistant.Entry{entry("hr-recruiter", "0.1.1", digestB), entry("hr-recruiter", "0.1.0", digestA)}
	if err := run(context.Background(), srv.Client(), srv.URL, testSHA, out, entries); err != nil {
		t.Fatal(err)
	}
	want := "hr-recruiter@0.1.1\tbash mctl-telegram/scripts/publish-assistant.sh hr-recruiter 0.1.1 " + testSHA + " " + digestB + "\n"
	if got := read(t, filepath.Join(out, "commands.tsv")); got != want {
		t.Fatalf("commands.tsv = %q, want %q", got, want)
	}
	var body struct {
		Version        string `json:"version"`
		Spec           string `json:"spec"`
		Owner          string `json:"owner"`
		SourceManifest struct {
			Repo, Path, GitSHA, ContentHash string
		} `json:"source_manifest"`
	}
	raw := read(t, filepath.Join(out, "hr-recruiter-0.1.1.request.json"))
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"git_sha":"` + testSHA + `"`, `"content_hash":"` + digestB + `"`,
		`"path":"assistants/hr-recruiter/versions/0.1.1/assistant.yaml"`, `"repo":"mctlhq/mctl-telegram"`} {
		if !strings.Contains(raw, k) {
			t.Errorf("request body lacks %s: %s", k, raw)
		}
	}
	if body.Version != "0.1.1" || body.Owner != "mctl-telegram" || body.Spec != `{"kind":"TelegramAssistant"}` {
		t.Fatalf("request body = %+v", body)
	}
	if _, err := os.Stat(filepath.Join(out, "hr-recruiter-0.1.0.request.json")); !os.IsNotExist(err) {
		t.Fatalf("a body was written for the published version: %v", err)
	}
	if s := read(t, filepath.Join(out, "summary.md")); !strings.Contains(s, "! bash mctl-telegram/scripts/publish-assistant.sh hr-recruiter 0.1.1") {
		t.Fatalf("summary does not carry the command:\n%s", s)
	}
}

func TestPublishedSameDigestPreparesNothing(t *testing.T) {
	for _, lifecycle := range []string{"published", "deprecated"} {
		srv, _ := registry(t, map[string]reply{"hr-recruiter@0.1.0": {200, catalogBody("hr-recruiter", "0.1.0", lifecycle, digestA)}})
		out := t.TempDir()
		if err := run(context.Background(), srv.Client(), srv.URL, testSHA, out, []*assistant.Entry{entry("hr-recruiter", "0.1.0", digestA)}); err != nil {
			t.Fatalf("%s: %v", lifecycle, err)
		}
		if got := read(t, filepath.Join(out, "commands.tsv")); got != "" {
			t.Fatalf("%s: commands.tsv = %q", lifecycle, got)
		}
	}
}

// blocked asserts the run failed and prepared no command and no body, for
// any version, including one observed as unpublished alongside.
func blocked(t *testing.T, fixture map[string]reply, entries []*assistant.Entry, wantNote string) {
	t.Helper()
	srv, _ := registry(t, fixture)
	out := t.TempDir()
	err := run(context.Background(), srv.Client(), srv.URL, testSHA, out, entries)
	if !errors.Is(err, errBlocked) {
		t.Fatalf("run = %v, want errBlocked", err)
	}
	if got := read(t, filepath.Join(out, "commands.tsv")); got != "" {
		t.Fatalf("commands.tsv = %q, want empty", got)
	}
	if m, _ := filepath.Glob(filepath.Join(out, "*.request.json")); len(m) != 0 {
		t.Fatalf("request bodies written: %v", m)
	}
	s := read(t, filepath.Join(out, "summary.md"))
	if !strings.Contains(s, "**Blocked.**") || !strings.Contains(s, wantNote) {
		t.Fatalf("summary lacks %q:\n%s", wantNote, s)
	}
}

func TestPublishedDifferentDigestFails(t *testing.T) {
	blocked(t, map[string]reply{
		"hr-recruiter@0.1.0": {200, catalogBody("hr-recruiter", "0.1.0", "published", digestB)},
		"hr-recruiter@0.1.1": {404, notFound},
	}, []*assistant.Entry{entry("hr-recruiter", "0.1.0", digestA), entry("hr-recruiter", "0.1.1", digestB)}, "digest mismatch")
}

func TestRegistryReadErrorIsUnknownNotUnpublished(t *testing.T) {
	cases := map[string]reply{
		"server error":            {500, `{"error":"failed to read assistant definition"}`},
		"404 from a proxy":        {404, `<html>Not Found</html>`},
		"404 with another code":   {404, `{"error":"not found","code":"version_not_found"}`},
		"unparsable 200":          {200, `{"name":`},
		"200 for another version": {200, catalogBody("hr-recruiter", "0.1.0", "published", digestB)},
		"200 without a digest":    {200, catalogBody("hr-recruiter", "0.1.1", "published", "")},
		"200 disabled":            {200, catalogBody("hr-recruiter", "0.1.1", "disabled", digestB)},
		"rate limited":            {429, `{"error":"slow down"}`},
	}
	for name, rep := range cases {
		t.Run(name, func(t *testing.T) {
			blocked(t, map[string]reply{
				"hr-recruiter@0.1.1": rep,
				"other@1.0.0":        {404, notFound},
			}, []*assistant.Entry{entry("hr-recruiter", "0.1.1", digestB), entry("other", "1.0.0", digestA)}, "unknown")
		})
	}
}

func TestUnreachableRegistryIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	out := t.TempDir()
	err := run(context.Background(), http.DefaultClient, base, testSHA, out, []*assistant.Entry{entry("hr-recruiter", "0.1.1", digestB)})
	if !errors.Is(err, errBlocked) {
		t.Fatalf("run = %v, want errBlocked", err)
	}
	if got := read(t, filepath.Join(out, "commands.tsv")); got != "" {
		t.Fatalf("commands.tsv = %q", got)
	}
}

func TestNonPublicDefinitionIsNotLookedUp(t *testing.T) {
	srv, calls := registry(t, map[string]reply{})
	e := entry("internal-helper", "1.0.0", digestA)
	e.Definition.Metadata.Visibility = "admin"
	out := t.TempDir()
	if err := run(context.Background(), srv.Client(), srv.URL, testSHA, out, []*assistant.Entry{e}); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatalf("%d registry calls for a definition the public catalog never shows", *calls)
	}
	if got := read(t, filepath.Join(out, "commands.tsv")); got != "" {
		t.Fatalf("commands.tsv = %q", got)
	}
	if s := read(t, filepath.Join(out, "summary.md")); !strings.Contains(s, "not publicly observable") {
		t.Fatalf("summary:\n%s", s)
	}
}

// The real catalog: every entry carries the source path a publish records.
func TestCatalogEntriesCarryTheirSource(t *testing.T) {
	c, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range c.Entries() {
		m := e.Definition.Metadata
		if e.Source != "assistants/"+m.Name+"/assistant.yaml" && e.Source != "assistants/"+m.Name+"/versions/"+m.Version+"/assistant.yaml" {
			t.Errorf("%s@%s: source %q", m.Name, m.Version, e.Source)
		}
		if _, err := assistant.PublishRequest(e, testSHA); err != nil {
			t.Errorf("%s@%s: %v", m.Name, m.Version, err)
		}
	}
}
