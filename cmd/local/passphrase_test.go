package main

import (
	"errors"
	"testing"
)

// TestPassphraseFromEnv covers how the daemon obtains its passphrase when
// there is no terminal — the case a service manager always presents.
func TestPassphraseFromEnv(t *testing.T) {
	const wrongFile = "/nope/passphrase"

	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	file := func(m map[string][]byte) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			data, ok := m[p]
			if !ok {
				return nil, errors.New("no such file")
			}
			return data, nil
		}
	}

	t.Run("nothing set leaves the caller to prompt", func(t *testing.T) {
		_, supplied, err := passphraseFromEnv(env(nil), file(nil))
		if err != nil || supplied {
			t.Fatalf("got supplied=%v err=%v, want false/nil", supplied, err)
		}
	})

	t.Run("plain variable", func(t *testing.T) {
		got, supplied, err := passphraseFromEnv(
			env(map[string]string{passphraseEnv: "hunter2"}), file(nil))
		if err != nil || !supplied || string(got) != "hunter2" {
			t.Fatalf("got %q supplied=%v err=%v", got, supplied, err)
		}
	})

	// The file form is the one documented for launchd and systemd, because a
	// plist and a unit file are both readable by every local account.
	t.Run("file wins over the plain variable", func(t *testing.T) {
		got, _, err := passphraseFromEnv(
			env(map[string]string{passphraseEnv: "from-env", passphraseFileEnv: "/p"}),
			file(map[string][]byte{"/p": []byte("from-file")}))
		if err != nil || string(got) != "from-file" {
			t.Fatalf("got %q err=%v, want from-file", got, err)
		}
	})

	// `echo secret > file` appends a newline that is not part of the
	// passphrase. Without trimming, the key check fails and blames the
	// passphrase rather than the newline.
	t.Run("trailing newline is not part of the passphrase", func(t *testing.T) {
		for _, raw := range []string{"hunter2\n", "hunter2\r\n", "hunter2\n\n"} {
			got, _, err := passphraseFromEnv(
				env(map[string]string{passphraseFileEnv: "/p"}),
				file(map[string][]byte{"/p": []byte(raw)}))
			if err != nil || string(got) != "hunter2" {
				t.Fatalf("raw %q: got %q err=%v", raw, got, err)
			}
		}
	})

	// Interior whitespace is somebody's deliberate passphrase.
	t.Run("leading and interior whitespace is preserved", func(t *testing.T) {
		got, _, err := passphraseFromEnv(
			env(map[string]string{passphraseFileEnv: "/p"}),
			file(map[string][]byte{"/p": []byte(" two words \n")}))
		if err != nil || string(got) != " two words " {
			t.Fatalf("got %q err=%v", got, err)
		}
	})

	// An unreadable or empty file must be an error, never a silent fall
	// through to the prompt: under a service manager there is no prompt, and
	// falling back would surface as a confusing terminal error instead of the
	// real cause.
	t.Run("unreadable file is an error, not a fallback", func(t *testing.T) {
		_, supplied, err := passphraseFromEnv(
			env(map[string]string{passphraseFileEnv: wrongFile}), file(nil))
		if err == nil || !supplied {
			t.Fatalf("got supplied=%v err=%v, want an error", supplied, err)
		}
	})

	t.Run("empty file is an error", func(t *testing.T) {
		_, _, err := passphraseFromEnv(
			env(map[string]string{passphraseFileEnv: "/p"}),
			file(map[string][]byte{"/p": []byte("\n")}))
		if err == nil {
			t.Fatal("an empty passphrase file must be rejected")
		}
	})
}
