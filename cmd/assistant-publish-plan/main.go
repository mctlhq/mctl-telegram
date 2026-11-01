// Command assistant-publish-plan works out which catalog assistant versions
// the mctl-api registry does not have yet and prepares their publication:
// for each one it writes the publish request body and the one command the
// owner runs to publish it (scripts/publish-assistant.sh). It never
// publishes: that is a human-admin call by design, so CI holds no
// credential for it (docs/assistants/spec.md, "Publishing").
//
// Each version is looked up on the public route
// GET /api/v1/assistant-catalog/{name}/versions/{version}, not in the
// catalog list, because the list leaves deprecated versions out. Only a
// 404 carrying code assistant_not_found counts as "not published"; any
// other failure is an unknown state. An unknown or a version the registry
// holds under a different digest fails the run, and then no command is
// written at all.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
)

type state string

const (
	statePublished   state = "published"
	stateUnpublished state = "unpublished"
	// stateMismatch is a version the registry holds under another digest:
	// published versions are immutable, so this is a broken invariant.
	stateMismatch state = "digest mismatch"
	// stateUnknown is a failed or unreadable registry read. It is never
	// taken for "not published".
	stateUnknown state = "unknown"
	// stateNotPublic is a definition the public catalog never shows
	// (visibility other than public, or status draft), so its absence
	// there says nothing. No command is prepared for it.
	stateNotPublic state = "not publicly observable"
)

type result struct {
	entry          *assistant.Entry
	state          state
	lifecycle      string
	registryDigest string
	detail         string
}

func (r result) key() string {
	return r.entry.Definition.Metadata.Name + "@" + r.entry.Definition.Metadata.Version
}

// errBlocked reports a run that found an unknown or a mismatch.
var errBlocked = errors.New("registry state is not fully known or contradicts the repository; no publish command prepared")

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func main() {
	registry := flag.String("registry", "https://api.mctl.ai", "mctl-api base URL")
	gitSHA := flag.String("git-sha", "", "the main commit the catalog was built from (required)")
	out := flag.String("out", "dist/assistant-publish", "directory for summary.md, commands.tsv and request bodies")
	flag.Parse()
	catalog, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		fmt.Fprintln(os.Stderr, "assistant-publish-plan:", err)
		os.Exit(1)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	if err := run(context.Background(), client, *registry, *gitSHA, *out, catalog.Entries()); err != nil {
		fmt.Fprintln(os.Stderr, "assistant-publish-plan:", err)
		os.Exit(1)
	}
}

// run observes every entry, writes summary.md always, and writes
// commands.tsv and the request bodies only when every version was observed
// and none contradicts the repository.
func run(ctx context.Context, client *http.Client, registry, gitSHA, out string, entries []*assistant.Entry) error {
	if gitSHA == "" {
		return errors.New("-git-sha is required")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i].Definition.Metadata, entries[j].Definition.Metadata
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	results := make([]result, 0, len(entries))
	blocked := false
	for _, e := range entries {
		r := observe(ctx, client, registry, e)
		if r.state == stateUnknown || r.state == stateMismatch {
			blocked = true
		}
		results = append(results, r)
	}

	var tsv strings.Builder
	commands := map[string]string{}
	if !blocked {
		for _, r := range results {
			if r.state != stateUnpublished {
				continue
			}
			body, err := assistant.PublishRequest(r.entry, gitSHA)
			if err != nil {
				return err
			}
			m := r.entry.Definition.Metadata
			if err := os.WriteFile(filepath.Join(out, m.Name+"-"+m.Version+".request.json"), body, 0o644); err != nil {
				return err
			}
			cmd := publishCommand(r.entry, gitSHA)
			commands[r.key()] = cmd
			fmt.Fprintf(&tsv, "%s\t%s\n", r.key(), cmd)
		}
	}
	if err := os.WriteFile(filepath.Join(out, "summary.md"), []byte(summary(results, commands, blocked)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "commands.tsv"), []byte(tsv.String()), 0o644); err != nil {
		return err
	}
	if blocked {
		return errBlocked
	}
	return nil
}

// publishCommand is what the owner runs from the workspace root. The digest
// is part of it so the script can refuse a rebuild that differs from what
// CI saw.
func publishCommand(e *assistant.Entry, gitSHA string) string {
	m := e.Definition.Metadata
	return fmt.Sprintf("bash mctl-telegram/scripts/publish-assistant.sh %s %s %s %s", m.Name, m.Version, gitSHA, e.Digest)
}

// observe reads one version from the public catalog route.
func observe(ctx context.Context, client *http.Client, registry string, e *assistant.Entry) result {
	m := e.Definition.Metadata
	r := result{entry: e}
	if m.Visibility != "public" || m.Status == "draft" {
		r.state = stateNotPublic
		r.detail = fmt.Sprintf("visibility %s, status %s", m.Visibility, m.Status)
		return r
	}
	unknown := func(format string, args ...any) result {
		r.state = stateUnknown
		r.detail = fmt.Sprintf(format, args...)
		return r
	}
	u := strings.TrimRight(registry, "/") + "/api/v1/assistant-catalog/" + url.PathEscape(m.Name) + "/versions/" + url.PathEscape(m.Version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return unknown("build request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return unknown("registry read failed: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return unknown("read response: %v", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		var got struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Lifecycle string `json:"lifecycle"`
			Digest    string `json:"digest"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			return unknown("200 with a body that is not a catalog entry: %v", err)
		}
		if got.Name != m.Name || got.Version != m.Version {
			return unknown("200 for %s@%s, asked for %s@%s", got.Name, got.Version, m.Name, m.Version)
		}
		if !digestPattern.MatchString(got.Digest) {
			return unknown("200 with digest %q, not a sha256 digest", got.Digest)
		}
		if got.Lifecycle != "published" && got.Lifecycle != "deprecated" {
			return unknown("200 with lifecycle %q, which this route never answers", got.Lifecycle)
		}
		r.lifecycle, r.registryDigest = got.Lifecycle, got.Digest
		if got.Digest != e.Digest {
			r.state = stateMismatch
			r.detail = "the registry holds this version under another digest; published versions are immutable"
			return r
		}
		r.state = statePublished
		return r
	case http.StatusNotFound:
		var got struct {
			Code string `json:"code"`
		}
		// A 404 from anything but the catalog handler (a proxy, a
		// misrouted path, an older API) is not the registry saying no.
		if err := json.Unmarshal(raw, &got); err != nil || got.Code != "assistant_not_found" {
			return unknown("404 without code assistant_not_found")
		}
		r.state = stateUnpublished
		return r
	default:
		return unknown("HTTP %d", resp.StatusCode)
	}
}

func summary(results []result, commands map[string]string, blocked bool) string {
	var b strings.Builder
	b.WriteString("## Assistant registry publish plan\n\n")
	b.WriteString("| Version | Repository digest | Registry | Note |\n|---|---|---|---|\n")
	for _, r := range results {
		reg := string(r.state)
		if r.lifecycle != "" {
			reg += ", lifecycle " + r.lifecycle
		}
		note := r.detail
		if r.state == stateMismatch {
			note += "; registry digest `" + r.registryDigest + "`"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", r.key(), r.entry.Digest, reg, note)
	}
	b.WriteString("\n")
	switch {
	case blocked:
		b.WriteString("**Blocked.** At least one version could not be observed or contradicts the repository, so no publish command is prepared. Rerun the job once the registry answers; a digest mismatch needs investigating, not publishing.\n")
	case len(commands) == 0:
		b.WriteString("Every observable version is already in the registry. Nothing to publish.\n")
	default:
		b.WriteString("Publishing is a human-admin step. From the workspace root, run for each version:\n\n")
		keys := make([]string, 0, len(commands))
		for k := range commands {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "- `%s`: `! %s`\n", k, commands[k])
		}
		b.WriteString("\nThe script rebuilds the document at that commit, checks the digest, publishes it and verifies the catalog. The request bodies are in the `assistant-publish-requests` artifact for reference only; the script does not use them.\n")
	}
	return b.String()
}
