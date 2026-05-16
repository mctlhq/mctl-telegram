package digest

import (
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestUntilNextHour(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 5, 16, h, m, 0, 0, time.UTC) }
	cases := []struct {
		now  time.Time
		hour int
		want time.Duration
	}{
		{at(8, 0), 9, time.Hour},
		{at(8, 30), 9, 30 * time.Minute},
		{at(10, 0), 9, 23 * time.Hour},
		{at(9, 0), 9, 24 * time.Hour}, // exactly on the hour → next day
	}
	for _, c := range cases {
		if got := untilNextHour(c.now, c.hour); got != c.want {
			t.Errorf("untilNextHour(%v, %d) = %v, want %v", c.now, c.hour, got, c.want)
		}
	}
}

func TestBuildDigestMessage(t *testing.T) {
	if msg := buildDigestMessage(nil, 0, false); msg != "" {
		t.Errorf("no new clients must produce an empty message, got %q", msg)
	}
	rows := []db.IdentityRow{
		{TelegramID: 111, Username: "alice", AccessTier: "client", HasSession: true},
		{TelegramID: 222, DisplayName: "Bob B", AccessTier: "", HasSession: false}, // unset tier
	}
	msg := buildDigestMessage(rows, 5, false)
	for _, want := range []string{"2 new client", "(5 total)", "alice", "id 111", "Bob B", "id 222"} {
		if !strings.Contains(msg, want) {
			t.Errorf("digest message missing %q; got:\n%s", want, msg)
		}
	}
	// Under auto-approve an unset-tier user must show as an effective client,
	// never "none" — that would imply the operator still has to act.
	autoMsg := buildDigestMessage(rows, 5, true)
	if !strings.Contains(autoMsg, "client (auto)") {
		t.Errorf("auto-approve digest should label unset users client (auto); got:\n%s", autoMsg)
	}
}

func TestEffectiveTier(t *testing.T) {
	cases := []struct {
		raw         string
		autoApprove bool
		want        string
	}{
		{"client", false, "client"},
		{"client", true, "client"},
		{"none", true, "none (banned)"},
		{"", false, "none"},
		{"", true, "client (auto)"},
	}
	for _, c := range cases {
		if got := effectiveTier(c.raw, c.autoApprove); got != c.want {
			t.Errorf("effectiveTier(%q, %v) = %q, want %q", c.raw, c.autoApprove, got, c.want)
		}
	}
}
