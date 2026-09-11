// Package scripts holds tests for the operator scripts in this directory.
// The scripts are shell, and the pre-flight in portal-allowlist-apply.sh is
// the one place where a mistake publishes an unreviewed allowlist to a shared
// surface, so it is exercised here rather than trusted to review.
package scripts

import (
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
		// dropGo runs the script with a PATH that has no go.
		dropGo bool
		want   string
	}{{
		name: "a committed file the guard passes reaches the API",
		// "read portal failed" comes from the stub curl, which is only
		// called after every pre-flight check has passed. It is the
		// positive case: there is no earlier success to observe.
		want: "read portal failed",
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
			dir := newFixture(t, tc.guardName, tc.guard)
			if tc.setup != nil {
				tc.setup(t, dir)
			}

			cmd := exec.Command("bash", filepath.Join(dir, "scripts", "portal-allowlist-apply.sh"), "--dry-run")
			path := filepath.Join(dir, "stub") + string(os.PathListSeparator) + os.Getenv("PATH")
			if tc.dropGo {
				path = filepath.Join(dir, "stub")
				for _, d := range []string{"/usr/bin", "/bin"} {
					path += string(os.PathListSeparator) + d
				}
			}
			cmd.Env = append(os.Environ(),
				"PATH="+path,
				"CLOUDFLARE_API_TOKEN=stub-token",
				"CLOUDFLARE_ACCOUNT_ID=stub-account",
			)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("the script succeeded; it reads a stub API and cannot:\n%s", out)
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
func newFixture(t *testing.T, guardName, guardBody string) string {
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
	write(t, filepath.Join(dir, "internal", "mcp", "guard_test.go"),
		"package mcp\n\nimport \"testing\"\n\nfunc "+guardName+"(t *testing.T) {\n\t"+guardBody+"\n}\n", 0o644)
	write(t, filepath.Join(dir, "stub", "curl"),
		"#!/bin/sh\nprintf '%s' '{\"success\":false,\"errors\":[{\"code\":0,\"message\":\"stub curl: no network in tests\"}]}'\n", 0o755)
	writeAllowlist(t, dir, "mcp", "tg", "")

	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "config", "user.email", "fixture@example.test")
	git(t, dir, "config", "user.name", "fixture")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-qm", "fixture")
	return dir
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
