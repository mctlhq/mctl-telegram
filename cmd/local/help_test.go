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
