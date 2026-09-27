package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Broadcast campaigns (issue-439). A campaign is created by a prepare call
// (the preview) and can only leave the prepared state through one of three
// guarded transitions:
//
//	prepared --approve (human, exact hashes, before expiry)--> approved
//	prepared --expiry observed--> expired
//	prepared|approved|sending --cancel--> cancelled
//
// approved -> sending -> completed belongs to the delivery worker. Every
// transition is a single conditional UPDATE on the current state, so
// approval is single-use by construction: a replayed approval finds the row
// no longer prepared and changes nothing.

// Campaign states.
const (
	CampaignPrepared  = "prepared"
	CampaignApproved  = "approved"
	CampaignSending   = "sending"
	CampaignCompleted = "completed"
	CampaignCancelled = "cancelled"
	CampaignExpired   = "expired"
)

// Errors returned by the guarded campaign transitions. Each names why the
// transition was refused; none of them leaves a partial write behind.
var (
	ErrCampaignNotFound    = errors.New("broadcast campaign not found")
	ErrCampaignExpired     = errors.New("broadcast campaign approval window has expired")
	ErrCampaignNotPrepared = errors.New("broadcast campaign is no longer awaiting approval")
	ErrCampaignMismatch    = errors.New("broadcast campaign content or selector does not match what was previewed")
	ErrCampaignTerminal    = errors.New("broadcast campaign has already finished")
)

// BroadcastRecipientFacts is everything the audience policy needs to decide
// one recipient, read in one pass. It deliberately carries no name, username
// or message history: eligibility never depends on them, so they are never
// loaded.
type BroadcastRecipientFacts struct {
	UserID             int64
	TelegramID         int64
	AccessTier         string // raw users.access_tier: "", "client" or "none"
	IdentityCapturedAt *time.Time
	LastSeenAt         *time.Time
	Reachability       string            // "" when never recorded
	Prefs              map[string]string // explicit rows only: category -> state
	ConnectedVia       []string          // live OAuth grants' client names
}

// ResolvePrefState returns the effective preference state for category given
// only the explicit rows in explicit (category -> state), applying the same
// default as ResolveNotificationPrefs when no row exists. Shared so the
// broadcast audience and the manage page can never disagree about a default.
func ResolvePrefState(category NotificationCategory, explicit map[string]string) string {
	if st, ok := explicit[string(category)]; ok {
		return st
	}
	return defaultPref(category).State
}

// ListBroadcastRecipientFacts returns facts for every users row with a
// Telegram login id, ordered by users.id so the preview sample and batch
// order are deterministic. It performs three fixed queries regardless of
// population size, and all three are full scans BY DESIGN: the recipient
// limit must be checked against the true eligible count, which a LIMITed page
// cannot give. Preview cost therefore grows with the user table; when that
// matters, the growth path is a server-side filter for connected_via and the
// activity window plus a paged fetch, as a deliberate later change.
func (s *Store) ListBroadcastRecipientFacts(ctx context.Context, now time.Time) ([]BroadcastRecipientFacts, error) {
	return s.broadcastFacts(ctx, now, 0)
}

// GetBroadcastRecipientFacts returns the facts for one user, or (nil, nil)
// when no users row with a Telegram login id exists for userID. The delivery
// worker calls it immediately before each send so an unsubscribe or a ban
// after approval is honoured.
func (s *Store) GetBroadcastRecipientFacts(ctx context.Context, userID int64, now time.Time) (*BroadcastRecipientFacts, error) {
	if userID <= 0 {
		return nil, errors.New("user id must be positive")
	}
	out, err := s.broadcastFacts(ctx, now, userID)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return &out[0], nil
}

func (s *Store) broadcastFacts(ctx context.Context, now time.Time, onlyUser int64) ([]BroadcastRecipientFacts, error) {
	filter, args := "", []any{}
	if onlyUser > 0 {
		filter, args = " AND u.id = $1", []any{onlyUser}
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT u.id, u.telegram_login_id, u.access_tier, u.identity_captured_at, u.last_seen_at, r.state
		   FROM users u
		   LEFT JOIN client_bot_reachability r ON r.user_id = u.id
		  WHERE u.telegram_login_id IS NOT NULL`+filter+`
		  ORDER BY u.id`, args...)
	if err != nil {
		return nil, fmt.Errorf("broadcast facts: %w", err)
	}
	var out []BroadcastRecipientFacts
	idx := map[int64]int{}
	for rows.Next() {
		var (
			f        BroadcastRecipientFacts
			tier     sql.NullString
			captured sql.NullTime
			seen     sql.NullTime
			reach    sql.NullString
		)
		if err := rows.Scan(&f.UserID, &f.TelegramID, &tier, &captured, &seen, &reach); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("broadcast facts: scan: %w", err)
		}
		f.AccessTier = tier.String
		if captured.Valid {
			t := captured.Time
			f.IdentityCapturedAt = &t
		}
		if seen.Valid {
			t := seen.Time
			f.LastSeenAt = &t
		}
		f.Reachability = reach.String
		f.Prefs = map[string]string{}
		idx[f.UserID] = len(out)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("broadcast facts: %w", err)
	}
	_ = rows.Close()
	if len(out) == 0 {
		return out, nil
	}

	prefQuery := `SELECT user_id, category, state FROM client_notification_prefs`
	if onlyUser > 0 {
		prefQuery += ` WHERE user_id = $1`
	}
	prows, err := s.DB.QueryContext(ctx, prefQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("broadcast facts: prefs: %w", err)
	}
	for prows.Next() {
		var (
			uid             int64
			category, state string
		)
		if err := prows.Scan(&uid, &category, &state); err != nil {
			_ = prows.Close()
			return nil, fmt.Errorf("broadcast facts: prefs scan: %w", err)
		}
		if i, ok := idx[uid]; ok {
			out[i].Prefs[category] = state
		}
	}
	if err := prows.Err(); err != nil {
		_ = prows.Close()
		return nil, fmt.Errorf("broadcast facts: prefs: %w", err)
	}
	_ = prows.Close()

	// Live OAuth grants only: the same non-expired, non-revoked predicate
	// the identity projection's connected_via uses, so "connected via
	// Claude" means a grant that could still be refreshed right now.
	clientQuery := `SELECT DISTINCT user_id, client_name FROM oauth_refresh_tokens
	                 WHERE client_name IS NOT NULL AND client_name <> ''
	                   AND revoked_at IS NULL AND expires_at > $1`
	cargs := []any{now}
	if onlyUser > 0 {
		clientQuery += ` AND user_id = $2`
		cargs = append(cargs, onlyUser)
	}
	crows, err := s.DB.QueryContext(ctx, clientQuery, cargs...)
	if err != nil {
		return nil, fmt.Errorf("broadcast facts: clients: %w", err)
	}
	defer func() { _ = crows.Close() }()
	for crows.Next() {
		var (
			uid  int64
			name string
		)
		if err := crows.Scan(&uid, &name); err != nil {
			return nil, fmt.Errorf("broadcast facts: clients scan: %w", err)
		}
		if i, ok := idx[uid]; ok {
			out[i].ConnectedVia = append(out[i].ConnectedVia, name)
		}
	}
	if err := crows.Err(); err != nil {
		return nil, fmt.Errorf("broadcast facts: clients: %w", err)
	}
	return out, nil
}

// BroadcastCampaign is one row of broadcast_campaigns. Content is the exact
// normalized text that was previewed and will be delivered; it is operator
// copy, not private chat content, but it is still never written to a log.
type BroadcastCampaign struct {
	ID             string
	State          string
	Category       string
	SelectorJSON   string
	SelectorHash   string
	Content        string
	ContentHash    string
	CreatedBy      int64
	Surface        string
	RecipientLimit int
	PreviewCounts  string // JSON: eligible + skipped-by-reason at prepare time
	ExpiresAt      time.Time
	ApprovedBy     *int64
	ApprovedAt     *time.Time
	CancelledBy    *int64
	CancelledAt    *time.Time
	CompletedAt    *time.Time
	// EndReason says why a campaign ended short of its audience (set by
	// the delivery worker); empty otherwise.
	EndReason string
	// SourceRef names the frozen product-update digest the campaign was
	// prepared from; nil for a manual campaign. Set at most once, by
	// SetBroadcastCampaignSourceRef.
	SourceRef *CampaignSourceRef
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateBroadcastCampaign inserts a new campaign in the prepared state. The
// caller computes the id, hashes, preview counts and expiry; now stamps
// created_at/updated_at from the same clock that computed the expiry.
func (s *Store) CreateBroadcastCampaign(ctx context.Context, c BroadcastCampaign, now time.Time) error {
	if c.ID == "" || c.ContentHash == "" || c.SelectorHash == "" || c.CreatedBy <= 0 {
		return errors.New("create broadcast campaign: id, hashes and creator are required")
	}
	now = now.UTC()
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO broadcast_campaigns(id, state, category, selector_json, selector_hash,
		     content, content_hash, created_by, surface, recipient_limit, preview_counts,
		     expires_at, created_at, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)`,
		c.ID, CampaignPrepared, c.Category, c.SelectorJSON, c.SelectorHash,
		c.Content, c.ContentHash, c.CreatedBy, c.Surface, c.RecipientLimit, c.PreviewCounts,
		c.ExpiresAt.UTC(), now,
	)
	if err != nil {
		return fmt.Errorf("create broadcast campaign: %w", err)
	}
	return nil
}

const campaignColumns = `id, state, category, selector_json, selector_hash, content, content_hash,
	created_by, surface, recipient_limit, preview_counts, expires_at, approved_by, approved_at,
	cancelled_by, cancelled_at, completed_at, end_reason, source_digest_id, source_digest_version,
	source_content_hash, created_at, updated_at`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCampaign(r rowScanner) (*BroadcastCampaign, error) {
	var (
		c                       BroadcastCampaign
		approvedBy, cancelledBy sql.NullInt64
		approvedAt, cancelledAt sql.NullTime
		completedAt             sql.NullTime
		srcID, srcHash          sql.NullString
		srcVersion              sql.NullInt64
	)
	if err := r.Scan(&c.ID, &c.State, &c.Category, &c.SelectorJSON, &c.SelectorHash, &c.Content,
		&c.ContentHash, &c.CreatedBy, &c.Surface, &c.RecipientLimit, &c.PreviewCounts, &c.ExpiresAt,
		&approvedBy, &approvedAt, &cancelledBy, &cancelledAt, &completedAt, &c.EndReason,
		&srcID, &srcVersion, &srcHash, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	if srcID.Valid {
		c.SourceRef = &CampaignSourceRef{DigestID: srcID.String, DigestVersion: int(srcVersion.Int64), ContentHash: srcHash.String}
	}
	if approvedBy.Valid {
		v := approvedBy.Int64
		c.ApprovedBy = &v
	}
	if approvedAt.Valid {
		t := approvedAt.Time
		c.ApprovedAt = &t
	}
	if cancelledBy.Valid {
		v := cancelledBy.Int64
		c.CancelledBy = &v
	}
	if cancelledAt.Valid {
		t := cancelledAt.Time
		c.CancelledAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time
		c.CompletedAt = &t
	}
	return &c, nil
}

// GetBroadcastCampaign returns one campaign or ErrCampaignNotFound.
func (s *Store) GetBroadcastCampaign(ctx context.Context, id string) (*BroadcastCampaign, error) {
	c, err := scanCampaign(s.DB.QueryRowContext(ctx,
		`SELECT `+campaignColumns+` FROM broadcast_campaigns WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCampaignNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get broadcast campaign: %w", err)
	}
	return c, nil
}

// MaxCampaignListLimit caps one ListBroadcastCampaigns page.
const MaxCampaignListLimit = 200

// ListBroadcastCampaigns returns campaigns in the given states (all states
// when none are given), newest first, at most limit rows (50 when limit is
// not positive, clamped to MaxCampaignListLimit).
func (s *Store) ListBroadcastCampaigns(ctx context.Context, limit int, states ...string) ([]BroadcastCampaign, error) {
	switch {
	case limit <= 0:
		limit = 50
	case limit > MaxCampaignListLimit:
		limit = MaxCampaignListLimit
	}
	q := `SELECT ` + campaignColumns + ` FROM broadcast_campaigns`
	args := []any{}
	if len(states) > 0 {
		ph := make([]string, len(states))
		for i, st := range states {
			args = append(args, st)
			ph[i] = fmt.Sprintf("$%d", i+1)
		}
		q += ` WHERE state IN (` + strings.Join(ph, ",") + `)`
	}
	args = append(args, limit)
	q += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(args))
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list broadcast campaigns: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []BroadcastCampaign
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, fmt.Errorf("list broadcast campaigns: scan: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ApproveBroadcastCampaign moves a prepared campaign to approved, recording
// the approver. The UPDATE is conditional on every binding at once -- state,
// expiry, content hash and selector hash -- so a replay, a late approval or
// an approval for different content can never succeed, and nothing is
// written when it does not. On refusal the row is re-read only to name the
// reason; an expired prepared campaign is moved to expired so it stops
// appearing as pending.
func (s *Store) ApproveBroadcastCampaign(ctx context.Context, id string, approver int64, contentHash, selectorHash string, now time.Time) error {
	if approver <= 0 {
		return errors.New("approver must be a known user")
	}
	now = now.UTC()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_campaigns
		    SET state = $2, approved_by = $3, approved_at = $4, updated_at = $4
		  WHERE id = $1 AND state = $5 AND expires_at > $4
		    AND content_hash = $6 AND selector_hash = $7`,
		id, CampaignApproved, approver, now, CampaignPrepared, contentHash, selectorHash,
	)
	if err != nil {
		return fmt.Errorf("approve broadcast campaign: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// The UPDATE may have committed; do not report a refusal for an
		// approval that might have taken effect.
		return fmt.Errorf("approve broadcast campaign: rows affected: %w", err)
	}
	if n == 1 {
		return nil
	}
	c, err := s.GetBroadcastCampaign(ctx, id)
	if err != nil {
		return err
	}
	switch {
	case c.State != CampaignPrepared:
		if c.State == CampaignExpired {
			return ErrCampaignExpired
		}
		return ErrCampaignNotPrepared
	case !c.ExpiresAt.After(now):
		if _, err := s.DB.ExecContext(ctx,
			`UPDATE broadcast_campaigns SET state = $2, updated_at = $3 WHERE id = $1 AND state = $4`,
			id, CampaignExpired, now, CampaignPrepared); err != nil {
			return fmt.Errorf("expire broadcast campaign: %w", err)
		}
		return ErrCampaignExpired
	default:
		return ErrCampaignMismatch
	}
}

// CancelBroadcastCampaign cancels a campaign that has not finished. Work the
// delivery worker has not yet sent is skipped once the state is cancelled;
// what was already delivered stays delivered and is reported as such.
func (s *Store) CancelBroadcastCampaign(ctx context.Context, id string, actor int64, now time.Time) error {
	if actor <= 0 {
		return errors.New("cancelling actor must be a known user")
	}
	now = now.UTC()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_campaigns
		    SET state = $2, cancelled_by = $3, cancelled_at = $4, updated_at = $4
		  WHERE id = $1 AND state IN ($5, $6, $7)`,
		id, CampaignCancelled, actor, now, CampaignPrepared, CampaignApproved, CampaignSending,
	)
	if err != nil {
		return fmt.Errorf("cancel broadcast campaign: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("cancel broadcast campaign: rows affected: %w", err)
	}
	if n == 1 {
		return nil
	}
	if _, err := s.GetBroadcastCampaign(ctx, id); err != nil {
		return err
	}
	return ErrCampaignTerminal
}

// ExpireBroadcastCampaigns moves every prepared campaign whose approval
// window has passed to expired, returning how many it moved.
func (s *Store) ExpireBroadcastCampaigns(ctx context.Context, now time.Time) (int64, error) {
	now = now.UTC()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_campaigns SET state = $1, updated_at = $2 WHERE state = $3 AND expires_at <= $2`,
		CampaignExpired, now, CampaignPrepared)
	if err != nil {
		return 0, fmt.Errorf("expire broadcast campaigns: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("expire broadcast campaigns: rows affected: %w", err)
	}
	return n, nil
}
