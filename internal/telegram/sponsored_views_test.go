package telegram

import (
	"fmt"
	"testing"
	"time"
)

// Synthetic users 4242 and 4343 read the same synthetic channel's ads.
func viewFixture(ids ...string) []SponsoredMessage {
	out := make([]SponsoredMessage, len(ids))
	for i, id := range ids {
		out[i] = SponsoredMessage{Channel: "channel:700100001", RandomID: id}
	}
	return out
}

func randomIDs(msgs []SponsoredMessage) []string {
	out := make([]string, len(msgs))
	for i, m := range msgs {
		out[i] = m.RandomID
	}
	return out
}

// claim is Claim without the token, for tests that do not release.
func claim(v *SponsoredViews, userID int64, msgs []SponsoredMessage) []SponsoredMessage {
	due, _ := v.Claim(userID, msgs)
	return due
}

func fakeClockViews(ttl time.Duration) (*SponsoredViews, *time.Time) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	v := NewSponsoredViews(ttl)
	v.now = func() time.Time { return now }
	return v, &now
}

func TestSponsoredViews_ReportedOncePerUserWithinTTL(t *testing.T) {
	v, now := fakeClockViews(5 * time.Minute)

	if got := randomIDs(claim(v, 4242, viewFixture("AQ==", "Ag=="))); fmt.Sprint(got) != "[AQ== Ag==]" {
		t.Fatalf("first read claimed %v, want both items", got)
	}
	// Paging the same channel serves the same items again.
	if got := claim(v, 4242, viewFixture("AQ==", "Ag==")); len(got) != 0 {
		t.Fatalf("second read within the TTL claimed %v, want none", randomIDs(got))
	}
	// Another user's view is a different impression.
	if got := claim(v, 4343, viewFixture("AQ==")); len(got) != 1 {
		t.Fatalf("other user claimed %v, want the item", randomIDs(got))
	}
	*now = now.Add(5*time.Minute - time.Second)
	if got := claim(v, 4242, viewFixture("AQ==")); len(got) != 0 {
		t.Fatalf("claimed %v just before the TTL ran out", randomIDs(got))
	}
	*now = now.Add(time.Second)
	if got := claim(v, 4242, viewFixture("AQ==")); len(got) != 1 {
		t.Fatalf("claimed %v after the TTL, want the item reported again", randomIDs(got))
	}
}

func TestSponsoredViews_DuplicateInOneCallAndMissingID(t *testing.T) {
	v, _ := fakeClockViews(time.Minute)
	got := randomIDs(claim(v, 4242, viewFixture("AQ==", "AQ==", "", "")))
	if fmt.Sprint(got) != "[AQ==  ]" {
		t.Fatalf("claimed %q, want the item once and both id-less items", got)
	}
}

func TestSponsoredViews_ReleaseLetsAFailedReportGoAgain(t *testing.T) {
	v, _ := fakeClockViews(time.Minute)
	_, tok := v.Claim(4242, viewFixture("AQ==", "Ag=="))
	v.Release(4242, tok, viewFixture("Ag=="))
	if got := randomIDs(claim(v, 4242, viewFixture("AQ==", "Ag=="))); fmt.Sprint(got) != "[Ag==]" {
		t.Fatalf("claimed %v, want only the released item", got)
	}
}

func TestSponsoredViews_NilReportsEverything(t *testing.T) {
	var v *SponsoredViews
	if got := claim(v, 4242, viewFixture("AQ==", "AQ==")); len(got) != 2 {
		t.Fatalf("nil set claimed %v, want every item", randomIDs(got))
	}
	v.Release(4242, 0, viewFixture("AQ==")) // must not panic
}

func TestSponsoredViews_SweepDropsExpiredUsers(t *testing.T) {
	v, now := fakeClockViews(time.Minute)
	claim(v, 4242, viewFixture("AQ=="))
	*now = now.Add(2 * time.Minute)
	claim(v, 4343, viewFixture("Ag=="))
	if _, ok := v.users[4242]; ok {
		t.Fatal("an expired user's set survived the sweep")
	}
	if len(v.users[4343]) != 1 {
		t.Fatalf("live user's set = %v", v.users[4343])
	}
}

func TestSponsoredViews_FullSetIsCleared(t *testing.T) {
	v, _ := fakeClockViews(time.Hour)
	ids := make([]string, maxSponsoredViewsPerUser)
	for i := range ids {
		ids[i] = fmt.Sprintf("id-%d", i)
	}
	claim(v, 4242, viewFixture(ids...))
	if got := claim(v, 4242, viewFixture("id-0")); len(got) != 1 {
		t.Fatal("a full set was kept: the bound must clear it (re-report rather than grow)")
	}
	if n := len(v.users[4242]); n != 1 {
		t.Fatalf("set size after clearing = %d, want 1", n)
	}
}

// An entry expires on its own deadline, not only when the periodic sweep
// happens to run.
func TestSponsoredViews_ExpiresBetweenSweeps(t *testing.T) {
	v, now := fakeClockViews(5 * time.Minute)
	claim(v, 4343, viewFixture("Ag==")) // sweeps at t0
	*now = now.Add(4 * time.Minute)
	claim(v, 4242, viewFixture("AQ==")) // expires at t0+9m
	*now = now.Add(time.Minute)
	claim(v, 4343, viewFixture("Ag==")) // sweeps at t0+5m
	*now = now.Add(4 * time.Minute)     // t0+9m: next sweep not due until t0+10m
	if got := claim(v, 4242, viewFixture("AQ==")); len(got) != 1 {
		t.Fatalf("claimed %v at the entry's deadline, want it reported again", randomIDs(got))
	}
}

// A late Release for a failed report must not undo a later read's claim of
// the same item: that read reported it, so it must stay de-duplicated.
func TestSponsoredViews_ReleaseKeepsALaterClaim(t *testing.T) {
	v, now := fakeClockViews(5 * time.Minute)
	_, tokA := v.Claim(4242, viewFixture("AQ==")) // read A: its report will fail
	*now = now.Add(5 * time.Minute)               // A's entry expires
	if got, _ := v.Claim(4242, viewFixture("AQ==")); len(got) != 1 {
		t.Fatalf("read B claimed %v, want the expired item", randomIDs(got))
	}
	v.Release(4242, tokA, viewFixture("AQ==")) // A's report failed only now
	if got := claim(v, 4242, viewFixture("AQ==")); len(got) != 0 {
		t.Fatalf("claimed %v: A's Release undid B's claim", randomIDs(got))
	}
}
