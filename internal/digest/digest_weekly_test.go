package digest

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestScheduleUntil(t *testing.T) {
	// 2026-11-08 is a Sunday.
	sun := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	weekly := Schedule{HourUTC: 9, Weekly: true, Weekday: time.Monday}
	for _, c := range []struct {
		name  string
		sched Schedule
		now   time.Time
		want  time.Duration
	}{
		{"daily is unchanged", Schedule{HourUTC: 9}, sun, 23 * time.Hour},
		{"weekly: next Monday", weekly, sun, 23 * time.Hour},
		{"weekly: Monday before the hour", weekly, time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC), time.Hour},
		{"weekly: Monday at the hour waits a week", weekly, time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC), 7 * day},
		{"weekly: Monday after the hour waits a week", weekly, time.Date(2026, 11, 9, 9, 0, 1, 0, time.UTC), 7*day - time.Second},
		{"weekly: Sunday target on a Sunday after the hour", Schedule{HourUTC: 9, Weekly: true, Weekday: time.Sunday}, sun, 6*day + 23*time.Hour},
	} {
		if got := c.sched.Until(c.now); got != c.want {
			t.Errorf("%s: Until = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestScheduleWindowAndLabel(t *testing.T) {
	if got := (Schedule{HourUTC: 9}).Window(); got != day {
		t.Errorf("daily window = %v", got)
	}
	if got := (Schedule{Weekly: true}).Window(); got != 7*day {
		t.Errorf("weekly window = %v", got)
	}
	if windowLabel(day) != "24h" || windowLabel(7*day) != "7d" {
		t.Errorf("labels = %q, %q", windowLabel(day), windowLabel(7*day))
	}
}

func TestDigestHeaderNamesTheWindow(t *testing.T) {
	rows := []db.IdentityRow{{TelegramID: 1, Username: "alice"}}
	if m := buildDigestMessage(7*day, rows, 1, false, nil, nil); !strings.Contains(m, "in the last 7d") {
		t.Errorf("plain weekly header: %q", m)
	}
	h, err := buildDigestHTML(7*day, rows, 1, false, nil, nil)
	if err != nil || !strings.Contains(h, "in the last 7d") {
		t.Errorf("html weekly header: %q, %v", h, err)
	}
	if m := buildDigestMessage(day, rows, 1, false, nil, nil); !strings.Contains(m, "in the last 24h") {
		t.Errorf("plain daily header: %q", m)
	}
}

// A client that joined three days ago is in the weekly digest and not in the
// daily one.
func TestRunDigestWindow(t *testing.T) {
	ctx := context.Background()
	store := newDigestTestStore(t)
	id, err := store.EnsureUserByTelegramID(ctx, 700100401, "three_days", "Three")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx, `UPDATE users SET created_at=$1 WHERE id=$2`, time.Now().UTC().Add(-3*day), id); err != nil {
		t.Fatalf("age user: %v", err)
	}

	rt := &capturingRoundTripper{}
	withStubTransport(t, rt)
	runDigest(ctx, store, "test-token", []int64{999}, false, broadcast.FormatHTML, day)
	if len(rt.bodies) != 0 {
		t.Fatalf("daily digest must skip a 3-day-old client, sent %d", len(rt.bodies))
	}
	runDigest(ctx, store, "test-token", []int64{999}, false, broadcast.FormatHTML, 7*day)
	if len(rt.bodies) != 1 {
		t.Fatalf("weekly digest must include it, sent %d", len(rt.bodies))
	}
	form, _ := url.ParseQuery(rt.bodies[0])
	if !strings.Contains(form.Get("text"), "three_days") || !strings.Contains(form.Get("text"), "in the last 7d") {
		t.Fatalf("weekly body: %q", form.Get("text"))
	}
}
