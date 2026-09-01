// Package alerts holds no runtime code; it exists so the Prometheus rule
// files shipped in this directory can be validated by `go test ./...`.
package alerts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// runbookURLRe extracts the annotation value we care about. The rules are
// Helm-templated YAML, so parsing them as YAML would require rendering the
// chart; a targeted regex over the raw text is both sufficient and immune to
// template syntax.
var runbookURLRe = regexp.MustCompile(`runbook_url:\s*"([^"]+)"`)

// anchorRe matches the explicit HTML anchors the runbooks use. GitHub also
// generates implicit anchors from headings, but every anchor an alert links to
// is written explicitly, and relying on the explicit form keeps this check
// honest: a heading rename cannot silently satisfy it.
var anchorRe = regexp.MustCompile(`<a id="([^"]+)"></a>`)

// TestRunbookURLsResolve fails when an alert's runbook_url points at a
// document or anchor that does not exist.
//
// This is not hypothetical. Three alerts shipped with dangling anchors —
// MctlBridgeDaemonsFlapping, MctlTelegramLoginSlow and
// MctlTelegramLoginSendCodeStalls — so an on-call engineer following the link
// from a firing alert landed at the top of the runbook with no section for the
// alert they were holding. Nothing caught it because the link is a string in
// an annotation, and a string is valid YAML whatever it points at.
func TestRunbookURLsResolve(t *testing.T) {
	const repoPrefix = "https://github.com/mctlhq/mctl-telegram/blob/main/"

	repoRoot := filepath.Join("..", "..")

	rules, err := filepath.Glob("*.rules.yaml")
	if err != nil {
		t.Fatalf("glob rule files: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no *.rules.yaml files found; this test is in the wrong directory")
	}

	// Cache per target document so a runbook is read once however many alerts
	// point into it. A document that could not be read is cached as a nil map
	// alongside its error, so every alert pointing at it is reported rather
	// than only the first one to reach it.
	anchors := map[string]map[string]bool{}
	readErr := map[string]error{}

	for _, ruleFile := range rules {
		raw, err := os.ReadFile(ruleFile)
		if err != nil {
			t.Fatalf("read %s: %v", ruleFile, err)
		}

		for _, m := range runbookURLRe.FindAllStringSubmatch(string(raw), -1) {
			url := m[1]
			if !strings.HasPrefix(url, repoPrefix) {
				// An external link is somebody else's document to keep alive.
				continue
			}
			target, anchor, hasAnchor := strings.Cut(strings.TrimPrefix(url, repoPrefix), "#")

			docPath := filepath.Join(repoRoot, filepath.FromSlash(target))
			if _, ok := anchors[docPath]; !ok {
				doc, err := os.ReadFile(docPath)
				if err != nil {
					anchors[docPath] = nil
					readErr[docPath] = err
				} else {
					found := map[string]bool{}
					for _, a := range anchorRe.FindAllStringSubmatch(string(doc), -1) {
						found[a[1]] = true
					}
					anchors[docPath] = found
				}
			}
			if err := readErr[docPath]; err != nil {
				t.Errorf("%s: runbook_url %q points at a file that does not exist: %v", ruleFile, url, err)
				continue
			}
			if !hasAnchor {
				continue
			}
			if !anchors[docPath][anchor] {
				t.Errorf("%s: runbook_url %q has no matching <a id=%q> in %s — "+
					"an alert links to a section that does not exist", ruleFile, url, anchor, target)
			}
		}
	}
}
