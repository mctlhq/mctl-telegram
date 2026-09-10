// Command mcpprobe measures what an MCP endpoint does over the modern
// stateless protocol and over the legacy lifecycle, and prints a report that
// is safe to paste into an issue.
//
// It is a diagnostic, not a monitor. The production canary is a separate
// binary with separate paging semantics; this one is run by hand, or in a
// pipeline, to produce one row of compatibility evidence at a time.
//
// The bearer credential is read from an environment variable rather than a
// flag, because a flag lands in the shell history and in the process table.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/mcpprobe"
)

// Exit codes. A run that measured a failure and a run that could not be
// invoked at all are different outcomes and get different codes, so a
// pipeline can tell "the endpoint is wrong" from "you called me wrong".
const (
	exitOK = 0
	// exitFinding: the probe ran and the endpoint failed conformance, or the
	// endpoint could not be reached at all.
	exitFinding = 1
	// exitUsage: the probe itself was invoked wrongly.
	exitUsage = 2
	// exitUnmeasured: the probe ran cleanly but a mandatory cell never
	// executed, so the run proves nothing either way.
	exitUnmeasured = 3
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("mcpprobe", flag.ContinueOnError)
	var (
		url      = fs.String("url", "", "MCP endpoint to probe, including its path (required)")
		mode     = fs.String("mode", "", "protocol path: modern or legacy (required; there is no default)")
		legacyV  = fs.String("legacy-version", "", "protocol version to offer at initialize (required with -mode legacy)")
		tokenEnv = fs.String("token-env", "MCPPROBE_TOKEN", "environment variable holding the bearer credential")
		tool     = fs.String("tool", mcpprobe.DefaultTool, "read-only tool to invoke once")
		source   = fs.String("source", string(mcpprobe.SourceDirect), "evidence label: in-process-current-main, direct-deployed or cloudflare-portal")
		asJSON   = fs.Bool("json", false, "emit the report as JSON instead of a table")
		timeout  = fs.Duration("timeout", 15*time.Second, "per-request timeout")
		skipAuth = fs.Bool("skip-oauth", false, "skip the authorization-surface probe")
		gitRef   = fs.String("git-ref", "", "build under test; defaults to the current git revision when available")
	)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: mcpprobe -url <endpoint> -mode <modern|legacy> [flags]\n\n"+
			"The bearer credential is read from $%s (override with -token-env), never from a flag.\n\n",
			"MCPPROBE_TOKEN")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	opts := mcpprobe.Options{
		URL:           *url,
		Mode:          mcpprobe.Mode(*mode),
		LegacyVersion: *legacyV,
		Token:         os.Getenv(*tokenEnv),
		Tool:          *tool,
		Source:        mcpprobe.Source(*source),
		GitRef:        *gitRef,
		SkipOAuth:     *skipAuth,
		HTTPClient:    mcpprobe.NewHTTPClient(*timeout),
	}
	if opts.GitRef == "" {
		opts.GitRef = currentGitRef(ctx)
	}

	report, err := mcpprobe.Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcpprobe: %v\n", err)
		// Only a rejected configuration is a usage error. An endpoint that
		// could not be reached is a finding about the endpoint, and a
		// pipeline should be able to tell the two apart without parsing
		// this message.
		if errors.Is(err, mcpprobe.ErrInvalidOptions) {
			fs.Usage()
			return exitUsage
		}
		return exitFinding
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "mcpprobe: encode report: %v\n", err)
			return exitFinding
		}
	} else {
		printTable(report)
	}

	return exitCodeForSummary(string(report.Summary))
}

// exitCodeForSummary maps a run verdict to a process exit code.
//
// Only a run that measured everything and liked what it saw exits 0.
// finalize goes to some trouble to keep an unmeasured run out of PASS, and
// this is its only consumer: collapsing SKIPPED and PENDING-OPERATOR into
// success would hand that distinction back. It is reachable in exactly the
// row this tool exists for — against a gateway that answers a protocol
// violation with 401, every negative is recorded as unmeasured, the summary
// is SKIPPED, and a pipeline reading the exit code alone would conclude the
// binding was verified.
func exitCodeForSummary(summary string) int {
	switch summary {
	case "PASS":
		return exitOK
	case "FAIL", "BLOCKED":
		return exitFinding
	default:
		// SKIPPED and PENDING-OPERATOR: the run completed, and it did not
		// establish what it was asked to. Distinct from both, so a caller
		// can tell "this endpoint is wrong" from "go run it yourself".
		return exitUnmeasured
	}
}

// printTable renders the human view. It shows the same fields the JSON
// carries, because a reader who trusts one and not the other has no way to
// tell which is authoritative.
func printTable(r *mcpprobe.Report) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "source\t%s\n", r.Source)
	fmt.Fprintf(w, "mode\t%s (%s)\n", r.Mode, r.ProtocolVersion)
	fmt.Fprintf(w, "target\t%s\n", r.TargetHost)
	fmt.Fprintf(w, "summary\t%s\n", r.Summary)
	if r.Server.Name != "" {
		fmt.Fprintf(w, "server\t%s %s\n", r.Server.Name, r.Server.Version)
	}
	if len(r.Server.SupportedVersions) > 0 {
		fmt.Fprintf(w, "advertises\t%s\n", strings.Join(r.Server.SupportedVersions, ", "))
	}
	fmt.Fprintf(w, "session\t%s\n", describeSession(r.Session))
	if r.GitRef != "" {
		fmt.Fprintf(w, "git ref\t%s\n", r.GitRef)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "STEP\tMETHOD\tHTTP\tRPC\tOUTCOME\tREASON")
	for _, s := range append(append([]mcpprobe.Step{}, r.Steps...), r.Negatives...) {
		rpc := ""
		if s.JSONRPCode != nil {
			rpc = fmt.Sprint(*s.JSONRPCode)
		}
		status := ""
		if s.HTTPStatus != 0 {
			status = fmt.Sprint(s.HTTPStatus)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Label, s.Method, status, rpc, s.Outcome, s.Reason)
	}
	if r.OAuth != nil {
		as := r.OAuth.AuthorizationServer
		fmt.Fprintln(w)
		fmt.Fprintf(w, "authorization server\t%s\n", as.Outcome)
		if len(as.TokenEndpointAuthMethods) > 0 {
			fmt.Fprintf(w, "  advertised token auth\t%s\n", strings.Join(as.TokenEndpointAuthMethods, ", "))
		}
		fmt.Fprintf(w, "  accepts a public client\t%t\n", as.SupportsPublicClient)
		fmt.Fprintf(w, "  demands a client credential\t%t\n", as.RequiresClientCredential)
		fmt.Fprintf(w, "  PKCE S256\t%t\n", as.PKCES256)
		fmt.Fprintf(w, "unauthenticated challenge\t%s\n", r.OAuth.Unauthenticated.Outcome)
	}
	_ = w.Flush()
}

func describeSession(s mcpprobe.SessionInfo) string {
	if !s.HeaderPresent {
		return "none minted"
	}
	out := fmt.Sprintf("minted (%d chars)", s.IDLength)
	if s.Required != nil {
		if *s.Required {
			out += ", required"
		} else {
			out += ", not required"
		}
	}
	if s.ForeignAccepted != nil {
		if *s.ForeignAccepted {
			out += ", any well-formed value accepted"
		} else {
			out += ", bound to the issuing process"
		}
	}
	return out
}

// currentGitRef labels the report with the build under test. It is a
// convenience, not a requirement: outside a checkout the field stays empty
// rather than the run failing.
func currentGitRef(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--short", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
