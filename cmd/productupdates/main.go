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
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
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

// profileSnapshotPath is where a release commits one tool profile's surface.
// It matches mcp.ProfileDescriptorsFile; this command does not import the MCP
// server to learn a file name.
func profileSnapshotPath(profile string) string {
	return "docs/tool-descriptors." + profile + ".json"
}

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
	profiles, code := loadProfiles(repo, baseline, stderr)
	if code != exitOK {
		return code
	}
	report, err := productupdate.GateProfiles(feed, baseline, releases, previous, current, profiles)
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
	}
	// A profile's bootstrap window runs while the full surface has a
	// baseline, so its unverified claims are printed whatever the baseline.
	for _, u := range report.Unverified {
		_, _ = fmt.Fprintf(stderr, "productupdates: unverified until a release carries a snapshot: %s\n", u)
	}
	if !report.Passed() {
		for _, p := range report.Problems {
			_, _ = fmt.Fprintf(stderr, "productupdates: %s\n", p)
		}
		return exitFailed
	}
	return exitOK
}

// loadProfiles reads every tool profile's snapshot at HEAD, which must exist,
// and at the baseline, where it may not yet. A baseline file that exists but
// cannot be read is a failure, never "the profile is new": only git's own
// "no such path" answer means absent.
func loadProfiles(repo, baseline string, stderr io.Writer) (productupdate.Profiles, int) {
	var out productupdate.Profiles
	if baseline != "" {
		// Whether the baseline carries profile snapshots is read from its
		// tree, not from the profiles this build still defines: otherwise
		// renaming or deleting every profile would put the survivors back
		// into their bootstrap window and quiet the gate.
		carries, err := baselineCarriesProfileSnapshots(repo, baseline)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "productupdates: %v\n", err)
			if errors.Is(err, errUnreadableProfileSnapshot) {
				return out, exitFailed
			}
			return out, exitUsage
		}
		out.BaselineCarriesProfiles = carries
	}
	for _, name := range toolprofile.Names() {
		path := profileSnapshotPath(name)
		raw, err := os.ReadFile(filepath.Join(repo, path))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "productupdates: %v (every tool profile commits its snapshot)\n", err)
			return out, exitFailed
		}
		current, err := productupdate.ParseSnapshot(raw)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "productupdates: %s: %v\n", path, err)
			return out, exitFailed
		}
		ps := productupdate.ProfileSurface{Name: name, Current: current}
		if baseline != "" {
			present, err := gitHasPath(repo, baseline, path)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "productupdates: %v\n", err)
				return out, exitUsage
			}
			if present {
				old, err := git(repo, "show", baseline+":"+path)
				if err != nil {
					_, _ = fmt.Fprintf(stderr, "productupdates: %v\n", err)
					return out, exitUsage
				}
				prev, err := productupdate.ParseSnapshot([]byte(old))
				if err != nil {
					_, _ = fmt.Fprintf(stderr, "productupdates: %s:%s: %v\n", baseline, path, err)
					return out, exitFailed
				}
				ps.Previous = &prev
			}
		}
		out.Surfaces = append(out.Surfaces, ps)
	}
	return out, exitOK
}

// baselineCarriesProfileSnapshots reports whether rev's tree holds any
// profile snapshot, whatever the profile's name: a
// docs/tool-descriptors.<name>.json that parses as a snapshot labelled with a
// profile. The label decides, as it does at HEAD, so another file sharing
// the stem (a JSON Schema for the format, say) is not taken for one. ls-tree
// is not recursive, so only docs/ itself is listed, never docs/design/.
func baselineCarriesProfileSnapshots(repo, rev string) (bool, error) {
	out, err := git(repo, "ls-tree", "--name-only", rev, "--", "docs/")
	if err != nil {
		return false, err
	}
	// A readable profile snapshot decides at once, since no unreadable
	// candidate could change that answer. An unreadable one is only recorded
	// and reported after the loop, so the answer does not depend on how its
	// name sorts against a readable snapshot's.
	var unreadable error
	for _, path := range strings.Split(strings.TrimSpace(out), "\n") {
		if path == snapshotPath || !strings.HasPrefix(path, "docs/tool-descriptors.") || !strings.HasSuffix(path, ".json") {
			continue
		}
		raw, err := git(repo, "show", rev+":"+path)
		if err != nil {
			return false, err
		}
		snap, err := productupdate.ParseSnapshot([]byte(raw))
		if err == nil {
			if snap.Surface.Profile != "" {
				return true, nil
			}
			continue
		}
		// A file this build cannot parse is a lookalike only if it says so:
		// a JSON object with no surface.profile. One that names a profile, or
		// is not a JSON object at all, may be a profile snapshot in a format
		// this build rejects, and taking it for absent would put every
		// profile back into its bootstrap window.
		var probe struct {
			Surface struct {
				Profile string `json:"profile"`
			} `json:"surface"`
		}
		if jerr := json.Unmarshal([]byte(raw), &probe); (jerr != nil || probe.Surface.Profile != "") && unreadable == nil {
			unreadable = fmt.Errorf("%w: %s:%s: %v", errUnreadableProfileSnapshot, rev, path, err)
		}
	}
	return false, unreadable
}

// errUnreadableProfileSnapshot marks a baseline file that may be a profile
// snapshot but does not parse: the gate cannot tell whether the baseline
// carries profile snapshots, so it fails rather than guess.
var errUnreadableProfileSnapshot = errors.New("baseline file may be a profile snapshot but does not parse")

// gitHasPath reports whether rev's tree has path. git ls-tree prints nothing
// for a path the tree lacks and fails for a revision it cannot read, so the
// two are not confused.
func gitHasPath(repo, rev, path string) (bool, error) {
	out, err := git(repo, "ls-tree", "--name-only", rev, "--", path)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == path, nil
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
