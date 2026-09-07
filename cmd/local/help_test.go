package main

import "testing"

func TestWantsHelp(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{"--help"}, true},
		{[]string{"-h"}, true},
		{[]string{"--server", "https://tg.mctl.ai"}, false},
		{[]string{"--", "--help"}, false},
		{[]string{"--foo", "--help"}, true},
	}
	for _, tc := range cases {
		if got := wantsHelp(tc.args); got != tc.want {
			t.Errorf("wantsHelp(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

func TestResolveActivateTelegramID(t *testing.T) {
	id, fromLogin, err := resolveActivateTelegramID(42, 99)
	if err != nil || id != 42 || fromLogin {
		t.Fatalf("flag override: id=%d fromLogin=%v err=%v", id, fromLogin, err)
	}
	id, fromLogin, err = resolveActivateTelegramID(0, 99)
	if err != nil || id != 99 || !fromLogin {
		t.Fatalf("config fallback: id=%d fromLogin=%v err=%v", id, fromLogin, err)
	}
	_, _, err = resolveActivateTelegramID(0, 0)
	if err == nil {
		t.Fatal("expected an error when neither flag nor config has an id")
	}
	_, _, err = resolveActivateTelegramID(-1, 0)
	if err == nil {
		t.Fatal("negative flag id is missing, not a valid override")
	}
}

// TestShouldHarden pins the rule the startup repair pass is gated on. The
// direction of each case is the point: a command that reaches local state must
// harden even when its arguments look like help, because the alternative is a
// silent read under the old permissions.
func TestShouldHarden(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"no arguments", nil, false},
		{"version", []string{"version"}, false},
		{"help", []string{"help"}, false},
		{"bare -h", []string{"-h"}, false},
		{"init usage printed by main", []string{"init", "--help"}, false},
		{"daemon usage printed by main", []string{"daemon", "-h"}, false},
		{"init", []string{"init"}, true},
		{"daemon", []string{"daemon"}, true},
		{"login", []string{"login", "--phone", "+100"}, true},
		{"connect", []string{"connect", "--token", "x"}, true},
		// The FlagSet consumes -h as the value of --phone, so the run
		// continues into loadConfig and openLocalStore. A raw argv scan would
		// call this help and skip the repair; hardening a run that turns out
		// to print usage costs a tree walk, missing one costs a read under the
		// old DACL.
		{"-h consumed as a flag value", []string{"login", "--phone", "-h"}, true},
		{"unknown subcommand", []string{"nonsense"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldHarden(tc.args); got != tc.want {
				t.Errorf("shouldHarden(%q) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}
