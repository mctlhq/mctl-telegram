package db

import (
	"context"
	"errors"
	"testing"
)

// TestResolveNotificationPrefs_DefaultsWhenNoRows is T9: a user with zero
// preference rows resolves product_updates=unsubscribed,
// maintenance=subscribed, security=subscribed, all Explicit=false, with
// maintenance and security classified operational.
func TestResolveNotificationPrefs_DefaultsWhenNoRows(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	prefs, err := s.ResolveNotificationPrefs(ctx, uid)
	if err != nil {
		t.Fatalf("ResolveNotificationPrefs: %v", err)
	}
	if len(prefs) != 3 {
		t.Fatalf("got %d prefs, want 3", len(prefs))
	}
	byCategory := make(map[string]ResolvedPref, 3)
	for _, p := range prefs {
		byCategory[p.Category] = p
	}
	want := map[string]struct {
		state          string
		classification string
	}{
		string(CategoryProductUpdates): {PrefUnsubscribed, ClassificationMarketing},
		string(CategoryMaintenance):    {PrefSubscribed, ClassificationOperational},
		string(CategorySecurity):       {PrefSubscribed, ClassificationOperational},
	}
	for category, w := range want {
		p, ok := byCategory[category]
		if !ok {
			t.Fatalf("missing category %s in resolved output", category)
		}
		if p.State != w.state {
			t.Errorf("%s: state = %q, want %q", category, p.State, w.state)
		}
		if p.Classification != w.classification {
			t.Errorf("%s: classification = %q, want %q", category, p.Classification, w.classification)
		}
		if p.Explicit {
			t.Errorf("%s: Explicit = true, want false (no row exists)", category)
		}
		if p.DecidedAt != nil {
			t.Errorf("%s: DecidedAt = %v, want nil", category, p.DecidedAt)
		}
	}
}

// TestSetNotificationPrefs_UnsubscribeRecordsProvenance is T10: setting
// product_updates=unsubscribed writes decided_at, source, and Explicit=true,
// while leaving the other two categories without rows (still resolving to
// their defaults).
func TestSetNotificationPrefs_UnsubscribeRecordsProvenance(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	if err := s.SetNotificationPrefs(ctx, uid, map[string]string{
		string(CategoryProductUpdates): PrefUnsubscribed,
	}, "account_api"); err != nil {
		t.Fatalf("SetNotificationPrefs: %v", err)
	}

	prefs, err := s.ResolveNotificationPrefs(ctx, uid)
	if err != nil {
		t.Fatalf("ResolveNotificationPrefs: %v", err)
	}
	for _, p := range prefs {
		switch p.Category {
		case string(CategoryProductUpdates):
			if !p.Explicit {
				t.Error("product_updates: Explicit = false, want true")
			}
			if p.Source != "account_api" {
				t.Errorf("product_updates: source = %q, want account_api", p.Source)
			}
			if p.DecidedAt == nil {
				t.Error("product_updates: DecidedAt is nil, want stamped")
			}
			if p.State != PrefUnsubscribed {
				t.Errorf("product_updates: state = %q, want unsubscribed", p.State)
			}
		case string(CategoryMaintenance), string(CategorySecurity):
			if p.Explicit {
				t.Errorf("%s: Explicit = true, want false (untouched)", p.Category)
			}
		}
	}
}

// TestSetNotificationPrefs_PartialUpdateAndValidation is T11: a body naming
// only maintenance leaves product_updates untouched; an unknown category and
// an unknown state each fail with nothing written.
func TestSetNotificationPrefs_PartialUpdateAndValidation(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	if err := s.SetNotificationPrefs(ctx, uid, map[string]string{
		string(CategoryMaintenance): PrefUnsubscribed,
	}, "self_service_web"); err != nil {
		t.Fatalf("SetNotificationPrefs(maintenance): %v", err)
	}
	prefs, err := s.ResolveNotificationPrefs(ctx, uid)
	if err != nil {
		t.Fatalf("ResolveNotificationPrefs: %v", err)
	}
	for _, p := range prefs {
		if p.Category == string(CategoryProductUpdates) && p.Explicit {
			t.Error("product_updates became explicit after a maintenance-only update")
		}
		if p.Category == string(CategoryMaintenance) && p.State != PrefUnsubscribed {
			t.Errorf("maintenance: state = %q, want unsubscribed", p.State)
		}
	}

	// Unknown category: rejected, nothing written.
	err = s.SetNotificationPrefs(ctx, uid, map[string]string{"bogus_category": PrefSubscribed}, "account_api")
	if !errors.Is(err, ErrUnknownNotificationCategory) {
		t.Fatalf("unknown category error = %v, want ErrUnknownNotificationCategory", err)
	}
	// Unknown state: rejected, nothing written.
	err = s.SetNotificationPrefs(ctx, uid, map[string]string{string(CategorySecurity): "maybe"}, "account_api")
	if !errors.Is(err, ErrUnknownNotificationState) {
		t.Fatalf("unknown state error = %v, want ErrUnknownNotificationState", err)
	}
	// security must still be at its default (untouched by either rejected call).
	prefs, err = s.ResolveNotificationPrefs(ctx, uid)
	if err != nil {
		t.Fatalf("ResolveNotificationPrefs: %v", err)
	}
	for _, p := range prefs {
		if p.Category == string(CategorySecurity) && p.Explicit {
			t.Error("security became explicit despite both attempts being rejected")
		}
	}
}

// TestSetNotificationPrefs_MixedValidityWritesNothing asserts that a batch
// containing one good change and one invalid change writes NEITHER --
// validation runs before any write.
func TestSetNotificationPrefs_MixedValidityWritesNothing(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	err = s.SetNotificationPrefs(ctx, uid, map[string]string{
		string(CategoryProductUpdates): PrefUnsubscribed,
		"bogus":                        PrefSubscribed,
	}, "account_api")
	if !errors.Is(err, ErrUnknownNotificationCategory) {
		t.Fatalf("error = %v, want ErrUnknownNotificationCategory", err)
	}

	prefs, err := s.ResolveNotificationPrefs(ctx, uid)
	if err != nil {
		t.Fatalf("ResolveNotificationPrefs: %v", err)
	}
	for _, p := range prefs {
		if p.Explicit {
			t.Errorf("%s became explicit despite the batch being rejected", p.Category)
		}
	}
}
