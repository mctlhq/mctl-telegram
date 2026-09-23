package broadcast

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

func TestSelectorNormalize_EquivalentSelectorsHashEqual(t *testing.T) {
	a, err := Selector{Category: "maintenance", Tiers: []string{"admin", "Client", "client"}, ConnectedVia: []string{"ChatGPT", " claude "}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Selector{Category: " maintenance", Tiers: []string{"client", "admin"}, ConnectedVia: []string{"claude", "chatgpt", "Claude"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := a.CanonicalJSON()
	jb, _ := b.CanonicalJSON()
	if ja != jb || Hash(ja) != Hash(jb) {
		t.Fatalf("equivalent selectors differ:\n%s\n%s", ja, jb)
	}
	c, _ := Selector{Category: "maintenance", Tiers: []string{"client"}}.Normalize()
	jc, _ := c.CanonicalJSON()
	if Hash(jc) == Hash(ja) {
		t.Fatal("different audiences must hash differently")
	}
}

func TestSelectorNormalize_DefaultTierIsClientOnly(t *testing.T) {
	s, err := Selector{Category: "security"}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Tiers) != 1 || s.Tiers[0] != TierClient {
		t.Fatalf("default tiers = %v, want [client]", s.Tiers)
	}
	explicit, _ := Selector{Category: "security", Tiers: []string{"client"}}.Normalize()
	j1, _ := s.CanonicalJSON()
	j2, _ := explicit.CanonicalJSON()
	if j1 != j2 {
		t.Fatalf("implicit and explicit client tier must be the same selector: %s vs %s", j1, j2)
	}
}

func TestSelectorNormalize_Rejects(t *testing.T) {
	for name, sel := range map[string]Selector{
		"unknown category": {Category: "newsletter"},
		"empty category":   {},
		"unknown tier":     {Category: "maintenance", Tiers: []string{"banned"}},
		"empty client":     {Category: "maintenance", ConnectedVia: []string{" "}},
		"negative window":  {Category: "maintenance", ActiveWithinDays: -1},
		"huge window":      {Category: "maintenance", ActiveWithinDays: MaxActiveWithinDays + 1},
	} {
		if _, err := sel.Normalize(); !errors.Is(err, ErrInvalidSelector) {
			t.Errorf("%s: err = %v, want ErrInvalidSelector", name, err)
		}
	}
}

func TestNormalizeText(t *testing.T) {
	got, err := NormalizeText("  hello\r\nworld\r ")
	if err != nil || got != "hello\nworld" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := NormalizeText(" \n\t "); err == nil {
		t.Fatal("blank text must be refused")
	}
	if _, err := NormalizeText(strings.Repeat("я", MaxTextRunes)); err != nil {
		t.Fatalf("text at the rune limit must pass: %v", err)
	}
	if _, err := NormalizeText(strings.Repeat("я", MaxTextRunes+1)); err == nil {
		t.Fatal("text over the rune limit must be refused")
	}
	if _, err := NormalizeText("a\xffb"); err == nil {
		t.Fatal("invalid UTF-8 must be refused")
	}
}

func TestPolicyTierOf_MirrorsResolveScopesPrecedence(t *testing.T) {
	p := Policy{
		AdminTelegramIDs:       map[int64]bool{1: true},
		LookupAdminTelegramIDs: map[int64]bool{2: true, 1: true},
		ClientTelegramIDs:      map[int64]bool{3: true, 2: true, 4: true},
	}
	cases := []struct {
		id   int64
		raw  string
		want string
	}{
		{1, "", TierAdmin},             // admin wins over lookup
		{2, db.TierClient, ""},         // lookup admin wins over client, never a recipient
		{3, "", TierClient},            // env client allowlist
		{4, db.TierNone, ""},           // explicit DB ban beats env allowlist
		{5, db.TierClient, TierClient}, // DB grant
		{6, "", ""},                    // unset, no auto-approve
	}
	for _, c := range cases {
		if got := p.TierOf(c.id, c.raw); got != c.want {
			t.Errorf("TierOf(%d,%q) = %q, want %q", c.id, c.raw, got, c.want)
		}
	}
	p.AutoApproveClients = true
	if got := p.TierOf(6, ""); got != TierClient {
		t.Errorf("auto-approve: TierOf(6,\"\") = %q, want client", got)
	}
	if got := p.TierOf(4, db.TierNone); got != "" {
		t.Errorf("auto-approve must not unban: got %q", got)
	}
}

func facts(id int64) db.BroadcastRecipientFacts {
	captured := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return db.BroadcastRecipientFacts{
		UserID: id, TelegramID: 1000 + id, AccessTier: db.TierClient,
		IdentityCapturedAt: &captured, LastSeenAt: &captured,
		Prefs: map[string]string{},
	}
}

func mustSel(t *testing.T, s Selector) Selector {
	t.Helper()
	n, err := s.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	p := Policy{AdminTelegramIDs: map[int64]bool{1009: true}}
	maint := mustSel(t, Selector{Category: "maintenance"})
	product := mustSel(t, Selector{Category: "product_updates"})

	type tc struct {
		name string
		sel  Selector
		f    func() db.BroadcastRecipientFacts
		want Decision
	}
	eligible := Decision{InAudience: true, Eligible: true}
	cases := []tc{
		{"operational default is subscribed", maint, func() db.BroadcastRecipientFacts { return facts(1) }, eligible},
		{"marketing default is unsubscribed", product, func() db.BroadcastRecipientFacts { return facts(1) },
			Decision{InAudience: true, Reason: SkipUnsubscribed}},
		{"explicit marketing opt-in", product, func() db.BroadcastRecipientFacts {
			f := facts(1)
			f.Prefs[string(db.CategoryProductUpdates)] = db.PrefSubscribed
			return f
		}, eligible},
		{"explicit operational opt-out", maint, func() db.BroadcastRecipientFacts {
			f := facts(1)
			f.Prefs[string(db.CategoryMaintenance)] = db.PrefUnsubscribed
			return f
		}, Decision{InAudience: true, Reason: SkipUnsubscribed}},
		{"deleted or never-captured account", maint, func() db.BroadcastRecipientFacts {
			f := facts(1)
			f.IdentityCapturedAt = nil
			return f
		}, Decision{InAudience: true, Reason: SkipNoAccount}},
		{"banned", maint, func() db.BroadcastRecipientFacts {
			f := facts(1)
			f.AccessTier = db.TierNone
			return f
		}, Decision{InAudience: true, Reason: SkipPolicy}},
		{"admin not targeted by default", maint, func() db.BroadcastRecipientFacts { return facts(9) },
			Decision{InAudience: true, Reason: SkipPolicy}},
		{"admin targeted explicitly", mustSel(t, Selector{Category: "maintenance", Tiers: []string{"admin"}}),
			func() db.BroadcastRecipientFacts { return facts(9) }, eligible},
		{"blocked", maint, func() db.BroadcastRecipientFacts {
			f := facts(1)
			f.Reachability = notify.StateBlocked
			return f
		}, Decision{InAudience: true, Reason: SkipUnreachable}},
		{"cannot initiate", maint, func() db.BroadcastRecipientFacts {
			f := facts(1)
			f.Reachability = notify.StateCannotInitiate
			return f
		}, Decision{InAudience: true, Reason: SkipUnreachable}},
		{"unknown reachability is not unreachable", maint, func() db.BroadcastRecipientFacts {
			f := facts(1)
			f.Reachability = notify.StateUnknown
			return f
		}, eligible},
		{"unsubscribed wins over unreachable (fixed order)", maint, func() db.BroadcastRecipientFacts {
			f := facts(1)
			f.Prefs[string(db.CategoryMaintenance)] = db.PrefUnsubscribed
			f.Reachability = notify.StateBlocked
			return f
		}, Decision{InAudience: true, Reason: SkipUnsubscribed}},
		{"connected_via matches case-insensitively", mustSel(t, Selector{Category: "maintenance", ConnectedVia: []string{"claude"}}),
			func() db.BroadcastRecipientFacts {
				f := facts(1)
				f.ConnectedVia = []string{"Claude"}
				return f
			}, eligible},
		{"connected_via excludes from audience", mustSel(t, Selector{Category: "maintenance", ConnectedVia: []string{"chatgpt"}}),
			func() db.BroadcastRecipientFacts {
				f := facts(1)
				f.ConnectedVia = []string{"Claude"}
				return f
			}, Decision{}},
		{"activity window excludes stale user", mustSel(t, Selector{Category: "maintenance", ActiveWithinDays: 7}),
			func() db.BroadcastRecipientFacts { return facts(1) }, Decision{}},
		{"activity window keeps recent user", mustSel(t, Selector{Category: "maintenance", ActiveWithinDays: 30}),
			func() db.BroadcastRecipientFacts { return facts(1) }, eligible},
	}
	for _, c := range cases {
		if got := Evaluate(c.sel, c.f(), p, now); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestRedactID(t *testing.T) {
	if got := RedactID(123456789); got != "12…89" {
		t.Fatalf("got %q", got)
	}
	if got := RedactID(123); got != "****" {
		t.Fatalf("short id must be fully masked, got %q", got)
	}
}
