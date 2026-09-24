// Command tooldiff prints the deterministic difference between two MCP tool
// surfaces: the evidence a product update is drafted from (issue-440).
//
// During release preparation, diff the previous release's committed snapshot
// against the one this commit carries:
//
//	go run ./cmd/tooldiff \
//	  -old <(git show 0.68.0:docs/tool-descriptors.json) -from 0.68.0 \
//	  -new docs/tool-descriptors.json -to "$(git rev-parse HEAD)"
//
// Without -new it enumerates the registry of the code it was built from, so a
// working tree can be compared before its snapshot is regenerated. The output
// is JSON with sorted lists: the same two surfaces always print the same
// bytes. It drafts nothing and publishes nothing.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/productupdate"
)

const (
	exitOK = 0
	// exitFailed: a snapshot could not be read, or the two cannot be compared.
	exitFailed = 1
	// exitUsage: the command was invoked wrongly.
	exitUsage = 2
)

// report names both sides, so a diff pasted into a release or a product
// update draft carries the refs it was computed from.
type report struct {
	From string             `json:"from"`
	To   string             `json:"to"`
	Diff productupdate.Diff `json:"diff"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tooldiff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		oldPath = fs.String("old", "", "previous snapshot, e.g. <(git show <tag>:docs/tool-descriptors.json) (required)")
		newPath = fs.String("new", "", "current snapshot (default: enumerate this build's registry)")
		from    = fs.String("from", "", "ref the previous snapshot comes from, e.g. the previous release tag (required)")
		to      = fs.String("to", "", "ref the current snapshot comes from (required)")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *oldPath == "" || *from == "" || *to == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: tooldiff -old FILE -from REF [-new FILE] -to REF")
		return exitUsage
	}

	previous, err := readSnapshot(*oldPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "tooldiff: %s: %v\n", *oldPath, err)
		return exitFailed
	}
	var current productupdate.Snapshot
	if *newPath == "" {
		current, err = mcp.ToolDescriptors()
	} else {
		current, err = readSnapshot(*newPath)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "tooldiff: current surface: %v\n", err)
		return exitFailed
	}

	diff, err := productupdate.Compare(previous, current)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "tooldiff: %v\n", err)
		return exitFailed
	}
	encoded, err := json.MarshalIndent(report{From: *from, To: *to, Diff: diff}, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "tooldiff: %v\n", err)
		return exitFailed
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", encoded)
	return exitOK
}

func readSnapshot(path string) (productupdate.Snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return productupdate.Snapshot{}, fmt.Errorf("read: %w", err)
	}
	return productupdate.ParseSnapshot(raw)
}
