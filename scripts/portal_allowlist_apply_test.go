// Package scripts holds tests for the operator scripts in this directory.
// The scripts are shell, and the pre-flight in portal-allowlist-apply.sh is
// the one place where a mistake publishes an unreviewed allowlist to a shared
// surface, so it is exercised here rather than trusted to review.
package scripts

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The pre-flight refuses in a fixed order, so each case below is written to
// reach the check it is about: a fixture that trips an earlier one would pass
// the test while proving nothing about the later one.
func TestApplyPreflight(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script is bash; the cross-platform job builds, it does not run operator scripts")
	}
	for _, bin := range []string{"git", "jq", "go", "bash"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not on PATH", bin)
		}
	}

	cases := []struct {
		name string
		// setup mutates the fixture after it is committed.
		setup func(t *testing.T, dir string)
		// guard is the body of the fixture's own guard test.
		guard string
		// guardName lets a case rename the guard out from under the script.
		guardName string
		// guardImports is the fixture guard's import block, when it needs one.
		guardImports string
		// dropGo runs the script with a PATH that has no go.
		dropGo bool
		// args is the argv passed to the script, defaulting to {"--dry-run"}.
		// Existing cases leave this unset, so they are unaffected.
		args []string
		// wantCode asserts a specific exit code via exec.ExitError.ExitCode()
		// when non-zero. Left at zero, a case falls back to the pre-existing
		// "err == nil iff wantOK" check below.
		wantCode int
		// wantOK is set for a case that must get all the way through the
		// pre-flight; want is then matched against the --dry-run body.
		wantOK bool
		want   string
	}{{
		name: "a committed file the guard passes is applied",
		// The positive case: there is no earlier success to observe, so it
		// is asserted on the body the dry run prints, which only exists
		// once every pre-flight check has passed.
		wantOK: true,
		want:   `"name": "get_my_send_status"`,
	}, {
		name: "the guard test does not get the Cloudflare credential",
		// The pre-flight is the one step that runs code from the checkout.
		// The fixture's guard fails if the token is in its environment, so
		// this case goes red the moment the script stops removing it.
		guard: `if os.Getenv("CLOUDFLARE_API_TOKEN") != "" || os.Getenv("CLOUDFLARE_ACCOUNT_ID") != "" {
		t.Fatal("the guard test was handed the Cloudflare credential")
	}`,
		guardImports: `"os"`,
		wantOK:       true,
		want:         `"server_id": "tg"`,
	}, {
		name: "an edit made after the check is not what gets applied",
		// The guard test runs between the check and the build of the PUT
		// body, which is the TOCTOU window itself: here it rewrites the file
		// on disk to enable a mutating tool and then passes. The body is
		// built from the committed blob, so the edit is not in it.
		guard: `if err := os.WriteFile("../../docs/portal-allowlist.json", []byte(` + "`" + `{"portal":"mcp","server":"tg","default_disabled":true,
 "tools":[{"name":"get_my_send_status","enabled":true,"reason":"r"},{"name":"send_message","enabled":true,"reason":"poisoned"}]}` + "`" + `), 0o644); err != nil {
		t.Fatal(err)
	}`,
		guardImports: `"os"`,
		wantOK:       true,
		want:         `"name": "send_message",` + "\n" + `          "enabled": false`,
	}, {
		name:  "an uncommitted edit is refused",
		setup: func(t *testing.T, dir string) { writeAllowlist(t, dir, "mcp", "tg", "edited") },
		want:  "differs from HEAD",
	}, {
		name: "a staged but uncommitted edit is refused",
		// The index-relative `git diff --quiet -- <path>` form passes this
		// one; a staged edit is no more reviewed than an unstaged one.
		setup: func(t *testing.T, dir string) {
			writeAllowlist(t, dir, "mcp", "tg", "staged, never committed")
			git(t, dir, "add", "--", "docs/portal-allowlist.json")
		},
		want: "differs from HEAD",
	}, {
		name: "a file left on disk but removed from the repository is refused",
		// git diff HEAD -- <path> exits 0 for a path HEAD does not have,
		// however different the file on disk is. Tracking is checked first
		// for exactly this reason.
		setup: func(t *testing.T, dir string) {
			git(t, dir, "rm", "--cached", "-q", "--", "docs/portal-allowlist.json")
			git(t, dir, "commit", "-qm", "untrack")
			writeAllowlist(t, dir, "mcp", "tg", "edited while untracked")
		},
		want: "is not tracked",
	}, {
		name: "a committed file naming another server is refused",
		setup: func(t *testing.T, dir string) {
			writeAllowlist(t, dir, "mcp", "seerrsense", "")
			git(t, dir, "commit", "-qam", "retarget")
		},
		want: "expected mcp/tg",
	}, {
		name:   "a host without go is refused",
		dropGo: true,
		want:   "go is not installed here",
	}, {
		name:  "a checkout whose guard test fails is refused, and the reason is shown",
		guard: `t.Fatal("send_message is enabled with no reason")`,
		// The operator is told what the test said, not just that it spoke.
		want: "send_message is enabled with no reason",
	}, {
		name: "a guard test that no longer exists is refused",
		// go test -run exits 0 when nothing matches, so an exit status
		// alone would read a deleted guard as a passing one.
		guardName: "TestSomethingElseEntirely",
		want:      "the guard test did not pass",
	}, {
		name:  "a copy outside a checkout is refused",
		setup: func(t *testing.T, dir string) { os.RemoveAll(filepath.Join(dir, ".git")) },
		want:  "is not a git checkout",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := newFixture(t, tc.guardName, tc.guardImports, tc.guard)
			if tc.setup != nil {
				tc.setup(t, dir)
			}

			args := tc.args
			if len(args) == 0 {
				args = []string{"--dry-run"}
			}
			cmd := exec.Command("bash", append([]string{filepath.Join(dir, "scripts", "portal-allowlist-apply.sh")}, args...)...)
			path := filepath.Join(dir, "stub") + string(os.PathListSeparator) + os.Getenv("PATH")
			if tc.dropGo {
				// Not a trimmed PATH: on a host where go, git and jq share a
				// directory (a Homebrew prefix, say) trimming it would take
				// the others with it and the script would refuse for the
				// wrong reason. The sandbox links in exactly what the script
				// needs before the go check, and nothing else.
				path = sandboxWithoutGo(t, dir)
			}
			cmd.Env = append(os.Environ(),
				"PATH="+path,
				"CLOUDFLARE_API_TOKEN=stub-token",
				"CLOUDFLARE_ACCOUNT_ID=stub-account",
				"STUB_CURL_LOG="+filepath.Join(dir, "curl.log"),
			)
			out, err := cmd.CombinedOutput()
			if tc.wantOK && err != nil {
				t.Fatalf("the script failed, but this case must reach the dry-run body: %v\n%s", err, out)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("the script succeeded; this case must be refused:\n%s", out)
			}
			if tc.wantCode != 0 {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != tc.wantCode {
					t.Fatalf("want exit code %d, got %v:\n%s", tc.wantCode, err, out)
				}
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("output does not contain %q:\n%s", tc.want, out)
			}
		})
	}
}

// TestApplyCheck drives --check against the same throwaway checkouts, proving
// the detector both green and red: T1/T2 below are the mutation-proof pair
// the proposal requires in the PR body, differing in exactly one field of the
// stubbed live portal.
func TestApplyCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script is bash; the cross-platform job builds, it does not run operator scripts")
	}
	for _, bin := range []string{"git", "jq", "go", "bash"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not on PATH", bin)
		}
	}

	// The live portal that matches the fixture's committed decisions exactly:
	// default_disabled true, get_my_send_status enabled, send_message
	// disabled. T1 (green) and T2 (red) differ from this by exactly one field.
	const inSyncPortal = `{"success":true,"result":{"created_at":"t","servers":[
	  {"server_id":"tg","default_disabled":true,"updated_tools":[
	    {"name":"get_my_send_status","enabled":true},
	    {"name":"send_message","enabled":false}
	  ]}
	]}}`

	cases := []struct {
		name string
		// setup mutates the fixture (docs/portal-allowlist.json, usually)
		// after it is committed.
		setup func(t *testing.T, dir string)
		// portalBody is the raw envelope stubCurl serves for GET
		// /portals/mcp. Empty falls back to the stub's own hardcoded
		// (empty updated_tools) response.
		portalBody string
		dropGo     bool
		wantCode   int
		want       []string
		// wantEmptyLog additionally asserts the curl log recorded no call at
		// all -- for the guard-stage refusals, which must not reach the
		// network in the first place.
		wantEmptyLog bool
	}{{
		// T1: the green half of the mutation proof.
		name:       "in sync against a matching fixture exits 0",
		portalBody: inSyncPortal,
		wantCode:   0,
		want:       []string{"in sync: default_disabled=true tools=2 enabled=get_my_send_status"},
	}, {
		// T2: the red half -- exactly one field changed from T1's body.
		name: "send_message enabled live but disabled in the file is reported and exits 3",
		portalBody: `{"success":true,"result":{"created_at":"t","servers":[
		  {"server_id":"tg","default_disabled":true,"updated_tools":[
		    {"name":"get_my_send_status","enabled":true},
		    {"name":"send_message","enabled":true}
		  ]}
		]}}`,
		wantCode: 3,
		want:     []string{"drift: send_message portal=true file=false"},
	}, {
		// T3.
		name: "default_disabled differing is named and exits 3",
		portalBody: `{"success":true,"result":{"created_at":"t","servers":[
		  {"server_id":"tg","default_disabled":false,"updated_tools":[
		    {"name":"get_my_send_status","enabled":true},
		    {"name":"send_message","enabled":false}
		  ]}
		]}}`,
		wantCode: 3,
		want:     []string{"drift: default_disabled portal=false file=true"},
	}, {
		// T4, direction one: a tool live but not decided in the file.
		name: "a tool live but not decided in the file reads as file=absent",
		portalBody: `{"success":true,"result":{"created_at":"t","servers":[
		  {"server_id":"tg","default_disabled":true,"updated_tools":[
		    {"name":"get_my_send_status","enabled":true},
		    {"name":"send_message","enabled":false},
		    {"name":"legacy_tool","enabled":false}
		  ]}
		]}}`,
		wantCode: 3,
		want:     []string{"drift: legacy_tool portal=false file=absent"},
	}, {
		// T4, direction two: a tool the file decides but the portal has
		// dropped from updated_tools.
		name: "a tool the file decides but the portal has dropped reads as portal=absent",
		portalBody: `{"success":true,"result":{"created_at":"t","servers":[
		  {"server_id":"tg","default_disabled":true,"updated_tools":[
		    {"name":"get_my_send_status","enabled":true}
		  ]}
		]}}`,
		wantCode: 3,
		want:     []string{"drift: send_message portal=absent file=false"},
	}, {
		// T6: a synced tool with no decision in the file is drift under
		// --check, not the apply path's early refusal -- and the other
		// decided tool is still evaluated in the same run.
		name: "a synced tool with no decision in the file is drift, not the apply refusal",
		setup: func(t *testing.T, dir string) {
			writeAllowlistWithTools(t, dir, `{"name": "get_my_send_status", "enabled": true, "reason": "no side effects, returns nothing about a chat"}`)
			git(t, dir, "commit", "-qam", "drop the send_message decision")
		},
		portalBody: `{"success":true,"result":{"created_at":"t","servers":[
		  {"server_id":"tg","default_disabled":true,"updated_tools":[
		    {"name":"get_my_send_status","enabled":true}
		  ]}
		]}}`,
		wantCode: 3,
		want:     []string{"drift: send_message synced by the server with no decision in docs/portal-allowlist.json"},
	}, {
		// T7: a file entry for a tool the server has not synced is held
		// back by the apply and so is not drift -- it is named in the
		// summary instead.
		name: "a file entry for a tool the server has not synced is held back, not drift",
		setup: func(t *testing.T, dir string) {
			writeAllowlistWithTools(t, dir,
				`{"name": "get_my_send_status", "enabled": true, "reason": "no side effects, returns nothing about a chat"},`+
					`{"name": "send_message", "enabled": false},`+
					`{"name": "future_tool", "enabled": false}`)
			git(t, dir, "commit", "-qam", "add a decision for an unsynced tool")
		},
		portalBody: inSyncPortal,
		wantCode:   0,
		want: []string{
			"in sync: default_disabled=true tools=2 enabled=get_my_send_status",
			"held back (not synced by the server): future_tool",
		},
	}, {
		// T8, guard one of several: an uncommitted edit refuses --check
		// exactly as it refuses apply/dry-run, before any network call.
		name:         "check inherits the uncommitted-edit guard",
		setup:        func(t *testing.T, dir string) { writeAllowlist(t, dir, "mcp", "tg", "edited") },
		wantCode:     1,
		want:         []string{"differs from HEAD"},
		wantEmptyLog: true,
	}, {
		// T8, guard two: a host without go cannot run the guard test, so
		// --check is refused for the same reason apply is.
		name:         "check inherits the missing-go guard",
		dropGo:       true,
		wantCode:     1,
		want:         []string{"go is not installed here"},
		wantEmptyLog: true,
	}, {
		// T9, one of two: an unsuccessful API envelope is "could not check",
		// not "drift" -- nothing was measured.
		name:       "an unsuccessful API envelope exits 1, not 3",
		portalBody: `{"success":false,"errors":[{"code":1000,"message":"stub: portal read failed"}]}`,
		wantCode:   1,
		want:       []string{"read portal failed"},
	}, {
		// T9, two of two: a portal with no mapping for the server is the
		// same "could not check" status.
		name:       "a portal with no tg mapping exits 1, not 3",
		portalBody: `{"success":true,"result":{"created_at":"t","servers":[]}}`,
		wantCode:   1,
		want:       []string{"expected exactly one"},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := newFixture(t, "", "", "")
			if tc.setup != nil {
				tc.setup(t, dir)
			}

			logPath := filepath.Join(dir, "curl.log")
			path := filepath.Join(dir, "stub") + string(os.PathListSeparator) + os.Getenv("PATH")
			if tc.dropGo {
				path = sandboxWithoutGo(t, dir)
			}
			env := []string{
				"PATH=" + path,
				"CLOUDFLARE_API_TOKEN=stub-token",
				"CLOUDFLARE_ACCOUNT_ID=stub-account",
				"STUB_CURL_LOG=" + logPath,
			}
			if tc.portalBody != "" {
				bodyPath := filepath.Join(dir, "portal-body.json")
				write(t, bodyPath, tc.portalBody, 0o644)
				env = append(env, "STUB_PORTAL_BODY="+bodyPath)
			}

			cmd := exec.Command("bash", filepath.Join(dir, "scripts", "portal-allowlist-apply.sh"), "--check")
			cmd.Env = append(os.Environ(), env...)
			out, err := cmd.CombinedOutput()

			gotCode := 0
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("script did not exit cleanly: %v\n%s", err, out)
				}
				gotCode = exitErr.ExitCode()
			}
			if gotCode != tc.wantCode {
				t.Fatalf("want exit code %d, got %d:\n%s", tc.wantCode, gotCode, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(string(out), w) {
					t.Fatalf("output does not contain %q:\n%s", w, out)
				}
			}

			// T5: whatever a --check run finds, it must never write -- proven
			// here by the recorded call log, not by reading the script.
			//
			// The log has to be there for that proof to mean anything. Both
			// assertions below are gated on a successful read, so a stub that
			// stopped recording -- STUB_CURL_LOG no longer exported, the
			// append broken -- would skip them and leave every case passing
			// with write-prevention silently switched off. A case that
			// reaches the network must therefore show its reads in the log
			// before the absence of a PUT is allowed to mean anything.
			logBytes, readErr := os.ReadFile(logPath)
			if !tc.wantEmptyLog {
				if readErr != nil {
					t.Fatalf("no curl call log at %s; the no-PUT assertion below would be vacuous: %v", logPath, readErr)
				}
				if !strings.Contains(string(logBytes), "GET\t") {
					t.Fatalf("expected the portal and server reads in the call log, got:\n%s", logBytes)
				}
			}
			if readErr == nil && strings.Contains(string(logBytes), "PUT\t") {
				t.Fatalf("--check recorded a PUT in the call log:\n%s", logBytes)
			}
			if tc.wantEmptyLog && readErr == nil && len(logBytes) != 0 {
				t.Fatalf("expected no curl calls at all; call log:\n%s", logBytes)
			}
		})
	}
}

// TestApplyUsage covers --help/-h, an unknown flag, and too many positional
// arguments -- all of which must be answered without a Cloudflare
// credential, a git checkout or Go installed, since the script exits before
// any of that is touched.
func TestApplyUsage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script is bash; the cross-platform job builds, it does not run operator scripts")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash is not on PATH")
	}

	dir := t.TempDir()
	mkdirAll(t, dir, "scripts")
	script, err := os.ReadFile("portal-allowlist-apply.sh")
	if err != nil {
		t.Fatalf("read the script under test: %v", err)
	}
	scriptPath := filepath.Join(dir, "scripts", "portal-allowlist-apply.sh")
	write(t, scriptPath, string(script), 0o755)

	cases := []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{name: "--help exits 0 and names --check", args: []string{"--help"}, wantCode: 0, want: "--check"},
		{name: "-h exits 0 and names --check", args: []string{"-h"}, wantCode: 0, want: "--check"},
		{name: "an unknown flag exits 2", args: []string{"--bogus"}, wantCode: 2, want: "usage"},
		{name: "two positional arguments exit 2", args: []string{"--check", "extra"}, wantCode: 2, want: "usage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := exec.Command("bash", append([]string{scriptPath}, tc.args...)...)
			cmd.Env = os.Environ()
			out, err := cmd.CombinedOutput()
			gotCode := 0
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("script did not exit cleanly: %v\n%s", err, out)
				}
				gotCode = exitErr.ExitCode()
			}
			if gotCode != tc.wantCode {
				t.Fatalf("want exit code %d, got %d:\n%s", tc.wantCode, gotCode, out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("output does not contain %q:\n%s", tc.want, out)
			}
		})
	}
}

// newFixture builds a throwaway checkout shaped like this repository: the real
// script, a go module with a guard test of the given name and body, and a
// committed allowlist. The stub directory shadows curl so no case reaches the
// network; a case that gets that far has passed every pre-flight check, which
// is what the positive case asserts.
func newFixture(t *testing.T, guardName, guardImports, guardBody string) string {
	t.Helper()
	dir := t.TempDir()
	if guardName == "" {
		guardName = "TestPortalAllowlist_CoversEveryRegisteredTool"
	}

	mkdirAll(t, dir, "scripts", "docs", "internal/mcp", "stub")
	script, err := os.ReadFile("portal-allowlist-apply.sh")
	if err != nil {
		t.Fatalf("read the script under test: %v", err)
	}
	write(t, filepath.Join(dir, "scripts", "portal-allowlist-apply.sh"), string(script), 0o755)
	write(t, filepath.Join(dir, "go.mod"), "module fixture\n\ngo 1.26.6\n", 0o644)
	imports := "\"testing\""
	if guardImports != "" {
		imports += "\n\t" + guardImports
	}
	write(t, filepath.Join(dir, "internal", "mcp", "guard_test.go"),
		"package mcp\n\nimport (\n\t"+imports+"\n)\n\nfunc "+guardName+"(t *testing.T) {\n\t"+guardBody+"\n}\n", 0o644)
	write(t, filepath.Join(dir, "stub", "curl"), stubCurl, 0o755)
	writeAllowlist(t, dir, "mcp", "tg", "")

	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "config", "user.email", "fixture@example.test")
	git(t, dir, "config", "user.name", "fixture")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-qm", "fixture")
	return dir
}

// stubCurl answers the two reads the script makes, so a case that passes the
// pre-flight produces a real body instead of a network error. Every
// invocation is appended to $STUB_CURL_LOG as "method<TAB>url", so a case can
// prove by observation -- not by reading the script -- that no PUT went out.
// A PUT is answered with an unsuccessful envelope naming the unexpected
// write, rather than the normal canned response, so a stray write both fails
// the run and leaves evidence in the log. The portal GET is served from
// $STUB_PORTAL_BODY when that file exists, so a case can make the live
// portal match or differ from the fixture; otherwise it falls back to the
// hardcoded response below.
const stubCurl = `#!/bin/sh
method=GET
url=
prev=
for a in "$@"; do
  case "$prev" in
    -X) method="$a" ;;
  esac
  case "$a" in
    http*) url="$a" ;;
  esac
  prev="$a"
done

if [ -n "$STUB_CURL_LOG" ]; then
  printf '%s\t%s\n' "$method" "$url" >> "$STUB_CURL_LOG"
fi

if [ "$method" = "PUT" ]; then
  printf '%s' '{"success":false,"errors":[{"code":0,"message":"stub curl: unexpected write '"$method $url"'"}]}'
  exit 0
fi

case "$url" in
  */servers/*)
    printf '%s' '{"success":true,"result":{"tools":[{"name":"get_my_send_status"},{"name":"send_message"}]}}'
    exit 0
    ;;
  */portals/*)
    if [ -n "$STUB_PORTAL_BODY" ] && [ -f "$STUB_PORTAL_BODY" ]; then
      cat "$STUB_PORTAL_BODY"
    else
      printf '%s' '{"success":true,"result":{"created_at":"t","servers":[{"server_id":"tg","default_disabled":true,"updated_tools":[]}]}}'
    fi
    exit 0
    ;;
esac
printf '%s' '{"success":false,"errors":[{"code":0,"message":"stub curl: unexpected call"}]}'
`

// sandboxWithoutGo returns a PATH holding the stub curl and a link to each
// tool the script reaches for before it looks for go -- and no go, whatever
// the host's layout is.
func sandboxWithoutGo(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "nogo")
	mkdirAll(t, dir, "nogo")
	for _, tool := range []string{"bash", "sh", "dirname", "git", "jq"} {
		src, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
		if err := os.Symlink(src, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "stub", "curl"), filepath.Join(bin, "curl")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(bin, "go")); err == nil {
		t.Fatal("the sandbox has a go on it; the case would prove nothing")
	}
	return bin
}

func writeAllowlist(t *testing.T, dir, portal, server, reason string) {
	t.Helper()
	if reason == "" {
		reason = "no side effects, returns nothing about a chat"
	}
	body := `{
  "portal": "` + portal + `",
  "server": "` + server + `",
  "default_disabled": true,
  "tools": [
    {"name": "get_my_send_status", "enabled": true, "reason": "` + reason + `"},
    {"name": "send_message", "enabled": false}
  ]
}
`
	write(t, filepath.Join(dir, "docs", "portal-allowlist.json"), body, 0o644)
}

// writeAllowlistWithTools writes a committed mcp/tg allowlist whose "tools"
// array is exactly toolsJSON, verbatim -- for cases that need a decision set
// other than writeAllowlist's fixed two tools (a missing decision, or an
// extra one for a tool the server has not synced).
func writeAllowlistWithTools(t *testing.T, dir, toolsJSON string) {
	t.Helper()
	body := `{
  "portal": "mcp",
  "server": "tg",
  "default_disabled": true,
  "tools": [` + toolsJSON + `]
}
`
	write(t, filepath.Join(dir, "docs", "portal-allowlist.json"), body, 0o644)
}

func mkdirAll(t *testing.T, dir string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(s)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	// A fixture must not inherit the developer's git identity or hooks.
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}
