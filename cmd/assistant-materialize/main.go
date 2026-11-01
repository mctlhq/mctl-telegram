// Command assistant-materialize writes the registry form of every assistant
// in the compiled-in catalog: one canonical JSON document per name@version,
// with its instructions inlined, and prints each digest and source path. CI
// runs it on every build and keeps the output as an artifact; publishing a
// document to the mctl-api registry is a separate, human-admin step
// (docs/assistants/spec.md). With -git-sha it also writes the publish
// request body, <name>-<version>.request.json, for that commit, which is
// what scripts/publish-assistant.sh sends.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
)

func main() {
	out := flag.String("out", "dist/assistants", "directory to write <name>-<version>.json into")
	gitSHA := flag.String("git-sha", "", "also write <name>-<version>.request.json, the publish body for this commit")
	flag.Parse()
	if err := run(*out, *gitSHA); err != nil {
		fmt.Fprintln(os.Stderr, "assistant-materialize:", err)
		os.Exit(1)
	}
}

func run(out, gitSHA string) error {
	catalog, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		return err
	}
	entries := catalog.Entries()
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i].Definition.Metadata, entries[j].Definition.Metadata
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for _, e := range entries {
		// What gets published must parse back to the same entry.
		back, err := assistant.ParseMaterialized(e.Materialized)
		if err != nil {
			return fmt.Errorf("%s@%s: materialized form does not parse: %w",
				e.Definition.Metadata.Name, e.Definition.Metadata.Version, err)
		}
		if back.Digest != e.Digest {
			return fmt.Errorf("%s@%s: digest changes on round trip",
				e.Definition.Metadata.Name, e.Definition.Metadata.Version)
		}
		name := fmt.Sprintf("%s-%s.json", e.Definition.Metadata.Name, e.Definition.Metadata.Version)
		if err := os.WriteFile(filepath.Join(out, name), e.Materialized, 0o644); err != nil {
			return err
		}
		if gitSHA != "" {
			body, err := assistant.PublishRequest(e, gitSHA)
			if err != nil {
				return err
			}
			req := fmt.Sprintf("%s-%s.request.json", e.Definition.Metadata.Name, e.Definition.Metadata.Version)
			if err := os.WriteFile(filepath.Join(out, req), body, 0o644); err != nil {
				return err
			}
		}
		fmt.Printf("%s@%s %s %s %s\n", e.Definition.Metadata.Name, e.Definition.Metadata.Version, e.Digest, name, e.Source)
	}
	return nil
}
