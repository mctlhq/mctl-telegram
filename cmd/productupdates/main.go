// Command productupdates checks the curated product-update feed
// (docs/product-updates/*.yaml, issue-440).
//
//	go run ./cmd/productupdates validate
//	go run ./cmd/productupdates gate
//
// validate checks every entry on its own. gate additionally diffs the tool
// surface at HEAD (docs/tool-descriptors.json) against the latest release tag
// whose tree carries a snapshot, and fails unless every added or removed tool
// and every schema or annotation change since that release is covered by an
// approved entry -- and no entry claims a change the diff does not show. CI
// runs gate on every pull request, so a tool change and its product update
// land together. It publishes nothing and reads no CHANGELOG.md.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/productupdate"
)

const (
	exitOK = 0
	// exitFailed: the feed is invalid or the gate found an uncovered change.
	exitFailed = 1
	// exitUsage: the command was invoked wrongly, or git could not be read.
	exitUsage = 2
)

// snapshotPath is where every release commits its tool surface.
const snapshotPath = "docs/tool-descriptors.json"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: productupdates validate|gate [-repo DIR] [-baseline TAG]")
		return exitUsage
	}
	command, rest := args[0], args[1:]
	fs := flag.NewFlagSet("productupdates "+command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", ".", "repository root")
	baseline := fs.String("baseline", "", "release tag to diff against (gate; default: the latest release carrying "+snapshotPath+")")
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 {
		return exitUsage
	}
	switch command {
	case "validate":
		if *baseline != "" {
			_, _ = fmt.Fprintln(stderr, "productupdates: -baseline applies to gate only")
			return exitUsage
		}
	case "gate":
		if *baseline != "" && !productupdate.ValidRelease(*baseline) {
			_, _ = fmt.Fprintf(stderr, "productupdates: -baseline %q is not a MAJOR.MINOR.PATCH release tag\n", *baseline)
			return exitUsage
		}
	default:
		_, _ = fmt.Fprintf(stderr, "productupdates: unknown command %q\n", command)
		return exitUsage
	}
	feed, err := productupdate.LoadFeed(filepath.Join(*repo, productupdate.FeedDir))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "productupdates: %v\n", err)
		return exitFailed
	}
	if command == "validate" {
		_, _ = fmt.Fprintf(stdout, "%d product update(s) valid\n", len(feed.Entries))
		return exitOK
	}
	return gate(*repo, *baseline, feed, stdout, stderr)
}

func gate(repo, baseline string, feed productupdate.Feed, stdout, stderr io.Writer) int {
	tags, err := git(repo, "tag", "--list")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "productupdates: %v\n", err)
		return exitUsage
	}
	releases := strings.Fields(tags)
	if baseline == "" {
		baseline = productupdate.LatestRelease(releases, func(tag string) bool {
			_, err := git(repo, "cat-file", "-e", tag+":"+snapshotPath)
			return err == nil
		})
		// A shallow clone carries no tags, so "no baseline" there means "not
		// fetched", not "none exists". Judging the feed against that would fail
		// every entry that cites a release; refuse instead.
		if baseline == "" {
			shallow, err := git(repo, "rev-parse", "--is-shallow-repository")
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "productupdates: %v\n", err)
				return exitUsage
			}
			if strings.TrimSpace(shallow) == "true" {
				_, _ = fmt.Fprintln(stderr, "productupdates: gate needs the full history and tags (a shallow clone has none); fetch with fetch-depth 0")
				return exitUsage
			}
		}
	}
	var previous productupdate.Snapshot
	if baseline != "" {
		raw, err := git(repo, "show", baseline+":"+snapshotPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "productupdates: %v\n", err)
			return exitUsage
		}
		if previous, err = productupdate.ParseSnapshot([]byte(raw)); err != nil {
			_, _ = fmt.Fprintf(stderr, "productupdates: %s:%s: %v\n", baseline, snapshotPath, err)
			return exitFailed
		}
	}
	rawCurrent, err := os.ReadFile(filepath.Join(repo, snapshotPath))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "productupdates: %v\n", err)
		return exitFailed
	}
	current, err := productupdate.ParseSnapshot(rawCurrent)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "productupdates: %s: %v\n", snapshotPath, err)
		return exitFailed
	}
	report, err := productupdate.Gate(feed, baseline, releases, previous, current)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "productupdates: %v\n", err)
		return exitFailed
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "productupdates: %v\n", err)
		return exitFailed
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", encoded)
	if baseline == "" {
		_, _ = fmt.Fprintln(stderr, "productupdates: no release carries "+snapshotPath+" yet; nothing to require")
		for _, u := range report.Unverified {
			_, _ = fmt.Fprintf(stderr, "productupdates: unverified until a release carries a snapshot: %s\n", u)
		}
	}
	if !report.Passed() {
		for _, p := range report.Problems {
			_, _ = fmt.Fprintf(stderr, "productupdates: %s\n", p)
		}
		return exitFailed
	}
	return exitOK
}

func git(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(errOut.String()))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return out.String(), nil
}
