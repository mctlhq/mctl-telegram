package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

// TestResolveMCPToken covers how `connect` resolves the MCP token across its
// three sources: the literal --token value, --token-file <path>, and stdin
// (via --token-file - or its --token - alias).
func TestResolveMCPToken(t *testing.T) {
	const wrongFile = "/nope/token"

	file := func(m map[string][]byte) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			data, ok := m[p]
			if !ok {
				return nil, errors.New("no such file")
			}
			return data, nil
		}
	}
	noFile := file(nil)

	t.Run("plain --token passthrough", func(t *testing.T) {
		got, err := resolveMCPToken("abc123", "", strings.NewReader(""), noFile)
		if err != nil || got != "abc123" {
			t.Fatalf("got %q err=%v, want abc123/nil", got, err)
		}
	})

	t.Run("both empty returns empty with no error", func(t *testing.T) {
		got, err := resolveMCPToken("", "", strings.NewReader(""), noFile)
		if err != nil || got != "" {
			t.Fatalf("got %q err=%v, want empty/nil so the caller prints its usage hint", got, err)
		}
	})

	t.Run("--token-file happy path trims a trailing newline", func(t *testing.T) {
		got, err := resolveMCPToken("", "/p", strings.NewReader(""),
			file(map[string][]byte{"/p": []byte("secret-token\n")}))
		if err != nil || got != "secret-token" {
			t.Fatalf("got %q err=%v, want secret-token/nil", got, err)
		}
	})

	t.Run("--token-file trims a trailing CRLF", func(t *testing.T) {
		got, err := resolveMCPToken("", "/p", strings.NewReader(""),
			file(map[string][]byte{"/p": []byte("secret-token\r\n")}))
		if err != nil || got != "secret-token" {
			t.Fatalf("got %q err=%v, want secret-token/nil", got, err)
		}
	})

	t.Run("--token-file - reads and trims stdin", func(t *testing.T) {
		got, err := resolveMCPToken("", "-", strings.NewReader("from-stdin\n"), noFile)
		if err != nil || got != "from-stdin" {
			t.Fatalf("got %q err=%v, want from-stdin/nil", got, err)
		}
	})

	t.Run("--token - is equivalent to --token-file -", func(t *testing.T) {
		got, err := resolveMCPToken("-", "", strings.NewReader("from-stdin\r\n"), noFile)
		if err != nil || got != "from-stdin" {
			t.Fatalf("got %q err=%v, want from-stdin/nil", got, err)
		}
	})

	t.Run("--token and --token-file together is an error", func(t *testing.T) {
		got, err := resolveMCPToken("abc123", "/p", strings.NewReader(""),
			file(map[string][]byte{"/p": []byte("other-token\n")}))
		if err == nil {
			t.Fatalf("got %q err=nil, want a mutual-exclusion error and no token", got)
		}
		if got != "" {
			t.Fatalf("got %q, want an empty token alongside the error", got)
		}
	})

	// The "-" alias is a source like any other, so pairing it with an
	// explicit --token-file is the same two-sources conflict as above. This
	// direction regressed once: applying the alias before the exclusion
	// check rewrote tokenFile to "-", so the file path vanished and stdin
	// was read with no error -- while the mirror-image case below stayed
	// correct, which is what made the asymmetry easy to miss.
	t.Run("--token - with an explicit --token-file is an error, not a silent stdin read", func(t *testing.T) {
		got, err := resolveMCPToken("-", "/p", strings.NewReader("from-stdin\n"),
			file(map[string][]byte{"/p": []byte("from-file\n")}))
		if err == nil {
			t.Fatalf("got %q err=nil, want a mutual-exclusion error rather than a silent stdin read", got)
		}
		if got != "" {
			t.Fatalf("got %q, want an empty token alongside the error", got)
		}
	})

	// The stdin read is bounded, so a mistaken source cannot read until the
	// process dies. cap+1 is read deliberately: without it, "exactly cap
	// bytes" and "cap bytes and still going" look identical and an oversized
	// input would be silently truncated into a wrong token.
	t.Run("oversized stdin is refused rather than truncated", func(t *testing.T) {
		big := strings.NewReader(strings.Repeat("a", maxMCPTokenBytes+1))
		got, err := resolveMCPToken("", "-", big, noFile)
		if err == nil {
			t.Fatalf("got %q err=nil, want an over-size error", got)
		}
		if got != "" {
			t.Fatalf("got %q, want an empty token alongside the error", got)
		}
	})

	// The file branch is bounded by readTokenFile, the production reader,
	// rather than by the length check alone: os.ReadFile would have spent the
	// memory before the check could reject it, so the bound would have been
	// reported but never enforced. Exercised through the real reader on a real
	// file for that reason -- injecting a stub here would test the check and
	// miss the thing that does the bounding.
	t.Run("oversized --token-file is refused, and bounded by the reader itself", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "token")
		// Deliberately FAR over the cap, not cap+1: at cap+1 a bounded reader
		// and os.ReadFile return the same number of bytes, so the assertion
		// below could not tell them apart and would pass for either.
		if err := os.WriteFile(path, []byte(strings.Repeat("a", maxMCPTokenBytes*4)), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		got, err := resolveMCPToken("", path, strings.NewReader(""), readTokenFile)
		if err == nil {
			t.Fatalf("got %q err=nil, want an over-size error", got)
		}
		if got != "" {
			t.Fatalf("got %q, want an empty token alongside the error", got)
		}
		// readTokenFile must stop at cap+1, never read the whole file.
		data, rerr := readTokenFile(path)
		if rerr != nil {
			t.Fatalf("readTokenFile: %v", rerr)
		}
		if len(data) != maxMCPTokenBytes+1 {
			t.Fatalf("readTokenFile read %d bytes of a %d-byte file, want it to stop at %d",
				len(data), maxMCPTokenBytes*4, maxMCPTokenBytes+1)
		}
	})

	t.Run("a --token-file exactly at the cap is still accepted", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "token")
		exact := strings.Repeat("a", maxMCPTokenBytes)
		if err := os.WriteFile(path, []byte(exact), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		got, err := resolveMCPToken("", path, strings.NewReader(""), readTokenFile)
		if err != nil || got != exact {
			t.Fatalf("got %d bytes err=%v, want %d bytes and no error", len(got), err, maxMCPTokenBytes)
		}
	})

	t.Run("stdin exactly at the cap is still accepted", func(t *testing.T) {
		exact := strings.Repeat("a", maxMCPTokenBytes)
		got, err := resolveMCPToken("", "-", strings.NewReader(exact), noFile)
		if err != nil || got != exact {
			t.Fatalf("got %d bytes err=%v, want %d bytes and no error", len(got), err, maxMCPTokenBytes)
		}
	})

	// A read failure must surface, not be mistaken for an empty token: the
	// caller's next move differs entirely between "no token supplied" and
	// "the pipe broke".
	t.Run("a stdin read error is wrapped and propagated", func(t *testing.T) {
		got, err := resolveMCPToken("", "-", iotest.ErrReader(errors.New("pipe blew up")), noFile)
		if err == nil {
			t.Fatalf("got %q err=nil, want the read error propagated", got)
		}
		if !strings.Contains(err.Error(), "pipe blew up") {
			t.Fatalf("err = %v, want it to wrap the underlying read error", err)
		}
		if got != "" {
			t.Fatalf("got %q, want an empty token alongside the error", got)
		}
	})

	t.Run("--token with --token-file - is an error (the mirror image)", func(t *testing.T) {
		got, err := resolveMCPToken("abc123", "-", strings.NewReader("from-stdin\n"), noFile)
		if err == nil {
			t.Fatalf("got %q err=nil, want a mutual-exclusion error", got)
		}
		if got != "" {
			t.Fatalf("got %q, want an empty token alongside the error", got)
		}
	})

	t.Run("unreadable --token-file path names the path in the error", func(t *testing.T) {
		_, err := resolveMCPToken("", wrongFile, strings.NewReader(""), noFile)
		if err == nil || !strings.Contains(err.Error(), wrongFile) {
			t.Fatalf("got err=%v, want an error naming %s", err, wrongFile)
		}
	})

	t.Run("empty file content after trim is an error", func(t *testing.T) {
		_, err := resolveMCPToken("", "/p", strings.NewReader(""),
			file(map[string][]byte{"/p": []byte("\n")}))
		if err == nil {
			t.Fatal("an empty token file must be rejected")
		}
	})

	t.Run("empty stdin after trim is an error", func(t *testing.T) {
		_, err := resolveMCPToken("", "-", strings.NewReader("\n"), noFile)
		if err == nil {
			t.Fatal("empty stdin must be rejected")
		}
	})

	t.Run("empty stdin via --token - is an error", func(t *testing.T) {
		_, err := resolveMCPToken("-", "", strings.NewReader(""), noFile)
		if err == nil {
			t.Fatal("empty stdin must be rejected")
		}
	})
}
