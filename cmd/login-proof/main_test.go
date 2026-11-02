package main

import (
	"encoding/base64"
	"flag"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/loginproof"
)

func TestParseArgs(t *testing.T) {
	ok := map[string]loginproof.Mode{
		"qr":                           loginproof.ModeQR,
		"phone":                        loginproof.ModePhone,
		"phone -expect ok":             loginproof.ModePhone,
		"phone -expect wrong-password": loginproof.ModePhoneWrongPassword,
		"phone -expect expired-code":   loginproof.ModePhoneExpiredCode,
		"phone -expect=wrong-password": loginproof.ModePhoneWrongPassword,
	}
	for line, want := range ok {
		got, err := parseArgs(splitArgs(line))
		if err != nil || got.mode != want {
			t.Errorf("%q: mode=%v err=%v", line, got.mode, err)
		}
	}
}

func TestParseArgs_RejectsSecretFlags(t *testing.T) {
	for _, line := range []string{
		"phone -phone +15550100000", "phone -code 12345", "phone -password x",
		"qr -session x", "phone -expect nope", "bogus", "", "qr extra", "qr -expect ok",
	} {
		if _, err := parseArgs(splitArgs(line)); err == nil {
			t.Errorf("%q was accepted", line)
		}
	}
}

func TestFlagSetsHaveNoSecretFlags(t *testing.T) {
	for _, sub := range []string{"qr", "phone"} {
		fs, _ := newFlagSet(sub)
		fs.VisitAll(func(f *flag.Flag) {
			switch f.Name {
			case "expect":
			default:
				t.Errorf("%s: unexpected flag -%s", sub, f.Name)
			}
		})
	}
}

func TestTokenFromURL(t *testing.T) {
	raw := []byte{1, 2, 3, 250, 251}
	url := "tg://login?token=" + base64.RawURLEncoding.EncodeToString(raw)
	got, err := tokenFromURL(url)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"tg://login", "tg://login?token=", "tg://login?token=***"} {
		if _, err := tokenFromURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPhoneModeRefusesWithoutTerminal(t *testing.T) {
	t.Setenv("TG_PROOF_API_ID", "1")
	t.Setenv("TG_PROOF_API_HASH", "h")
	t.Setenv("TG_PROOF_EXPECT_TG_ID", "42")
	t.Setenv("TG_PROOF_PHONE", "+15550100000")
	out, _ := execute(options{mode: loginproof.ModePhone})
	if out != loginproof.OutcomeRefused {
		t.Fatalf("outcome = %s, want refused when stdin is not a terminal", out)
	}
}

func TestMissingEnvRefuses(t *testing.T) {
	t.Setenv("TG_PROOF_API_ID", "")
	if out, _ := execute(options{mode: loginproof.ModeQR}); out != loginproof.OutcomeRefused {
		t.Fatalf("outcome = %s", out)
	}
}

func splitArgs(s string) []string { return strings.Fields(s) }
