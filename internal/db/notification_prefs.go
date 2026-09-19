package db

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// NotificationCategory enumerates the notification categories a client can
// hold a preference for. Row-per-category (not a JSON blob) so decided_at
// and source are per-category and queryable on both dialects -- SQLite has
// no JSONB.
type NotificationCategory string

const (
	CategoryProductUpdates NotificationCategory = "product_updates"
	CategoryMaintenance    NotificationCategory = "maintenance"
	CategorySecurity       NotificationCategory = "security"
)

// notificationCategories is the closed set SetNotificationPrefs and
// ResolveNotificationPrefs validate against. Order matters only for
// ResolveNotificationPrefs's deterministic output order.
var notificationCategories = []NotificationCategory{
	CategoryProductUpdates,
	CategoryMaintenance,
	CategorySecurity,
}

// Preference states stored in client_notification_prefs.state.
const (
	PrefSubscribed   = "subscribed"
	PrefUnsubscribed = "unsubscribed"
)

// Preference classification: travels with the category (never with the raw
// state alone) so a future sender cannot conflate an operational notice with
// marketing consent.
const (
	ClassificationMarketing   = "marketing"
	ClassificationOperational = "operational"
)

// ErrUnknownNotificationCategory is returned by SetNotificationPrefs when the
// changes map names a category outside the closed set. Nothing is written.
var ErrUnknownNotificationCategory = errors.New("unknown notification category")

// ErrUnknownNotificationState is returned by SetNotificationPrefs when a
// change names a state other than "subscribed"/"unsubscribed". Nothing is
// written.
var ErrUnknownNotificationState = errors.New("unknown notification state")

// ResolvedPref is the resolved (default-applied) view of one category's
// preference, returned by Store.ResolveNotificationPrefs and embedded in the
// admin projection (IdentityRow.NotificationPrefs).
type ResolvedPref struct {
	Category       string     `json:"category"`
	State          string     `json:"state"`
	Explicit       bool       `json:"explicit"`
	Classification string     `json:"classification"`
	Source         string     `json:"source,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
}

// defaultPref returns the Go-computed default for a category when no
// explicit row exists. Defaults are never written as rows -- see
// ResolveNotificationPrefs -- so "never decided" stays distinguishable from
// "decided, then unsubscribed".
//
//   - product_updates defaults to unsubscribed: marketing consent must be an
//     affirmative act.
//   - maintenance and security default to subscribed and are classified
//     operational, so a future sender can never count them as marketing
//     consent.
func defaultPref(category NotificationCategory) ResolvedPref {
	switch category {
	case CategoryProductUpdates:
		return ResolvedPref{
			Category:       string(category),
			State:          PrefUnsubscribed,
			Explicit:       false,
			Classification: ClassificationMarketing,
		}
	case CategoryMaintenance, CategorySecurity:
		return ResolvedPref{
			Category:       string(category),
			State:          PrefSubscribed,
			Explicit:       false,
			Classification: ClassificationOperational,
		}
	default:
		return ResolvedPref{Category: string(category), State: PrefUnsubscribed, Explicit: false}
	}
}

func isKnownCategory(category string) bool {
	for _, c := range notificationCategories {
		if string(c) == category {
			return true
		}
	}
	return false
}

// ResolveNotificationPrefs returns every category's resolved preference for
// userID: an explicit row if one exists, else the Go-computed default. Order
// is fixed (product_updates, maintenance, security) regardless of how many
// rows exist.
func (s *Store) ResolveNotificationPrefs(ctx context.Context, userID int64) ([]ResolvedPref, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT category, state, source, decided_at FROM client_notification_prefs WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve notification prefs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	explicit := make(map[string]ResolvedPref, len(notificationCategories))
	for rows.Next() {
		var (
			category  string
			state     string
			source    string
			decidedAt time.Time
		)
		if err := rows.Scan(&category, &state, &source, &decidedAt); err != nil {
			return nil, fmt.Errorf("scan notification pref: %w", err)
		}
		classification := ClassificationMarketing
		if NotificationCategory(category) == CategoryMaintenance || NotificationCategory(category) == CategorySecurity {
			classification = ClassificationOperational
		}
		dAt := decidedAt
		explicit[category] = ResolvedPref{
			Category:       category,
			State:          state,
			Explicit:       true,
			Classification: classification,
			Source:         source,
			DecidedAt:      &dAt,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("resolve notification prefs: %w", err)
	}

	out := make([]ResolvedPref, 0, len(notificationCategories))
	for _, c := range notificationCategories {
		if p, ok := explicit[string(c)]; ok {
			out = append(out, p)
			continue
		}
		out = append(out, defaultPref(c))
	}
	return out, nil
}

// SetNotificationPrefs applies a partial set of category -> state changes for
// userID, all inside one transaction. Only the categories present in changes
// are touched; every other category is left exactly as it was (including
// "never explicitly decided"). An unknown category or state rejects the
// WHOLE call with nothing written -- validation runs before any write.
func (s *Store) SetNotificationPrefs(ctx context.Context, userID int64, changes map[string]string, source string) error {
	if len(changes) == 0 {
		return nil
	}
	if source == "" {
		return errors.New("source is required")
	}
	for category, state := range changes {
		if !isKnownCategory(category) {
			return fmt.Errorf("%w: %s", ErrUnknownNotificationCategory, category)
		}
		if state != PrefSubscribed && state != PrefUnsubscribed {
			return fmt.Errorf("%w: %s", ErrUnknownNotificationState, state)
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set notification prefs: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	// Iterate in sorted key order, not map order: this INSERT ... ON
	// CONFLICT DO UPDATE takes a row lock per category, and Go's
	// non-deterministic map iteration would let two concurrent callers for
	// the same userID acquire those locks in opposite order across
	// categories, risking a DB deadlock. Sorting fixes one global lock
	// order for every caller.
	categories := make([]string, 0, len(changes))
	for category := range changes {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	for _, category := range categories {
		state := changes[category]
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO client_notification_prefs(user_id, category, state, source, decided_at, created_at, updated_at)
			 VALUES($1,$2,$3,$4,$5,$5,$5)
			 ON CONFLICT (user_id, category) DO UPDATE SET
			     state = EXCLUDED.state,
			     source = EXCLUDED.source,
			     decided_at = EXCLUDED.decided_at,
			     updated_at = EXCLUDED.updated_at`,
			userID, category, state, source, now,
		); err != nil {
			return fmt.Errorf("set notification pref %s: %w", category, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("set notification prefs: commit: %w", err)
	}
	return nil
}

// purgeNotificationState deletes both new (issue-438) tables for userID
// within the caller's transaction. Explicit deletes rather than relying on
// ON DELETE CASCADE -- the users identity row survives account deletion, so
// these must be removed the same explicit way purgeAgentData removes the
// agent-domain rows, or a deleted account's consent record and reachability
// state would outlive the deletion.
func purgeNotificationState(ctx context.Context, ex execer, userID int64) error {
	stmts := []string{
		`DELETE FROM client_notification_prefs WHERE user_id = $1`,
		`DELETE FROM client_bot_reachability WHERE user_id = $1`,
	}
	for _, q := range stmts {
		if _, err := ex.ExecContext(ctx, q, userID); err != nil {
			return fmt.Errorf("purge notification state: %w", err)
		}
	}
	return nil
}
