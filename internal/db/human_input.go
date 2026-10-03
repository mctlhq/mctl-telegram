package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Human-input delivery states (issue-571). A row is created `queued` together
// with its owner_notifications row, becomes `sent` when the notifier delivers
// it, and ends in one terminal state.
const (
	HumanInputQueued     = "queued"
	HumanInputSent       = "sent"
	HumanInputAnswered   = "answered"
	HumanInputInactive   = "inactive"
	HumanInputSuperseded = "superseded"
	HumanInputRejected   = "rejected"
)

// ErrHumanInputCodeConflict means the generated answer code already exists for
// the user; the caller retries with a fresh code.
var ErrHumanInputCodeConflict = errors.New("human input answer code already in use")

// ErrHumanInputDeliveryNotFound means no delivery row matches the lookup.
var ErrHumanInputDeliveryNotFound = errors.New("human input delivery not found")

// HumanInputDelivery correlates one (user, request_id, request_hash) with the
// answer code shown to the owner. It carries ids, hashes and state only: no
// question, why, option label or answer text.
type HumanInputDelivery struct {
	ID             int64
	UserID         int64
	RequestID      string
	RequestHash    string
	RequestVersion int64
	WorkItemID     string
	Kind           string
	AnswerCode     string
	OptionIDs      []string
	MaxLength      int
	NotificationID int64
	TGMessageID    int64
	State          string
	LastOutcome    string
	DeliveredAt    time.Time
	RespondedAt    time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Terminal reports whether the row can no longer take an answer.
func (d HumanInputDelivery) Terminal() bool {
	return d.State != HumanInputQueued && d.State != HumanInputSent
}

const humanInputDeliveryCols = `id, user_id, request_id, request_hash, request_version, work_item_id, kind,
	answer_code, option_ids_json, max_length, notification_id, tg_message_id, state, last_outcome,
	delivered_at, responded_at, created_at, updated_at`

func scanHumanInputDelivery(sc interface{ Scan(...any) error }) (HumanInputDelivery, error) {
	var (
		d                        HumanInputDelivery
		optionsJSON              string
		notifID, tgMsgID         sql.NullInt64
		deliveredAt, respondedAt sql.NullTime
	)
	if err := sc.Scan(&d.ID, &d.UserID, &d.RequestID, &d.RequestHash, &d.RequestVersion, &d.WorkItemID, &d.Kind,
		&d.AnswerCode, &optionsJSON, &d.MaxLength, &notifID, &tgMsgID, &d.State, &d.LastOutcome,
		&deliveredAt, &respondedAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return HumanInputDelivery{}, err
	}
	if err := json.Unmarshal([]byte(optionsJSON), &d.OptionIDs); err != nil {
		return HumanInputDelivery{}, fmt.Errorf("decode option ids: %w", err)
	}
	d.NotificationID = notifID.Int64
	d.TGMessageID = tgMsgID.Int64
	if deliveredAt.Valid {
		d.DeliveredAt = deliveredAt.Time
	}
	if respondedAt.Valid {
		d.RespondedAt = respondedAt.Time
	}
	return d, nil
}

// UpsertHumanInputDeliveryTx inserts the delivery row for (user, request_id,
// request_hash) and, in the same transaction, queues the owner_notifications
// row of kind human_input carrying body. It is idempotent: when the triple
// already has a row it changes nothing and returns inserted=false. A code
// collision with another of the user's codes returns
// ErrHumanInputCodeConflict (nothing written) so the caller can retry with a
// fresh code. d.AnswerCode, d.Kind and the ids are required; body is the
// pre-rendered message, sealed like every owner notification body.
func (s *Store) UpsertHumanInputDeliveryTx(ctx context.Context, d HumanInputDelivery, body string) (inserted bool, err error) {
	if d.UserID <= 0 || d.RequestID == "" || d.RequestHash == "" || d.Kind == "" || d.AnswerCode == "" {
		return false, errors.New("user id, request id, request hash, kind and answer code are required")
	}
	var exists int
	switch qerr := s.DB.QueryRowContext(ctx,
		`SELECT 1 FROM human_input_deliveries WHERE user_id = $1 AND request_id = $2 AND request_hash = $3`,
		d.UserID, d.RequestID, d.RequestHash).Scan(&exists); {
	case qerr == nil:
		return false, nil
	case !errors.Is(qerr, sql.ErrNoRows):
		return false, fmt.Errorf("check human input delivery: %w", qerr)
	}
	optionsJSON, err := json.Marshal(append([]string{}, d.OptionIDs...))
	if err != nil {
		return false, fmt.Errorf("encode option ids: %w", err)
	}
	sealed, err := s.Crypt.SealForUser([]byte(body), d.UserID)
	if err != nil {
		return false, fmt.Errorf("seal human input body: %w", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin human input delivery: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	var deliveryID int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO human_input_deliveries(user_id, request_id, request_hash, request_version, work_item_id,
		     kind, answer_code, option_ids_json, max_length, state, created_at, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 ON CONFLICT DO NOTHING
		 RETURNING id`,
		d.UserID, d.RequestID, d.RequestHash, d.RequestVersion, d.WorkItemID,
		d.Kind, d.AnswerCode, string(optionsJSON), d.MaxLength, HumanInputQueued, now, now,
	).Scan(&deliveryID)
	if errors.Is(err, sql.ErrNoRows) {
		// Either a concurrent writer took the triple, or the code collided.
		_ = tx.Rollback()
		switch qerr := s.DB.QueryRowContext(ctx,
			`SELECT 1 FROM human_input_deliveries WHERE user_id = $1 AND request_id = $2 AND request_hash = $3`,
			d.UserID, d.RequestID, d.RequestHash).Scan(&exists); {
		case qerr == nil:
			return false, nil
		case errors.Is(qerr, sql.ErrNoRows):
			return false, ErrHumanInputCodeConflict
		default:
			return false, fmt.Errorf("recheck human input delivery: %w", qerr)
		}
	}
	if err != nil {
		return false, fmt.Errorf("insert human input delivery: %w", err)
	}
	var notifID int64
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO owner_notifications(user_id, kind, body_encrypted, status)
		 VALUES($1,$2,$3,$4) RETURNING id`,
		d.UserID, NotificationHumanInput, sealed, NotificationPending,
	).Scan(&notifID); err != nil {
		return false, fmt.Errorf("queue human input notification: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE human_input_deliveries SET notification_id = $1 WHERE id = $2`, notifID, deliveryID); err != nil {
		return false, fmt.Errorf("link human input notification: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit human input delivery: %w", err)
	}
	return true, nil
}

// GetHumanInputDeliveryByCode looks up a delivery by (user_id, answer_code).
// The lookup is per user, so one owner can never address another's code.
func (s *Store) GetHumanInputDeliveryByCode(ctx context.Context, userID int64, code string) (HumanInputDelivery, error) {
	d, err := scanHumanInputDelivery(s.DB.QueryRowContext(ctx,
		`SELECT `+humanInputDeliveryCols+` FROM human_input_deliveries WHERE user_id = $1 AND answer_code = $2`,
		userID, code))
	if errors.Is(err, sql.ErrNoRows) {
		return HumanInputDelivery{}, ErrHumanInputDeliveryNotFound
	}
	if err != nil {
		return HumanInputDelivery{}, fmt.Errorf("get human input delivery: %w", err)
	}
	return d, nil
}

// ListOpenHumanInputDeliveries returns the user's non-terminal rows (queued or
// sent), oldest first.
func (s *Store) ListOpenHumanInputDeliveries(ctx context.Context, userID int64) ([]HumanInputDelivery, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT `+humanInputDeliveryCols+` FROM human_input_deliveries
		  WHERE user_id = $1 AND state IN ($2, $3) ORDER BY id`,
		userID, HumanInputQueued, HumanInputSent)
	if err != nil {
		return nil, fmt.Errorf("list open human input deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []HumanInputDelivery
	for rows.Next() {
		d, err := scanHumanInputDelivery(rows)
		if err != nil {
			return nil, fmt.Errorf("scan human input delivery: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkHumanInputDelivery moves a non-terminal row to state with outcome. It is
// a compare-and-set from queued|sent, so a terminal row is never rewritten;
// changed reports whether this call made the transition. When the row was
// still queued, its not-yet-sent notification is retired so a stale question
// is never delivered.
func (s *Store) MarkHumanInputDelivery(ctx context.Context, userID, id int64, state, outcome string) (changed bool, err error) {
	now := time.Now().UTC()
	var respondedAt any
	if state == HumanInputAnswered || state == HumanInputRejected {
		respondedAt = now
	}
	var wasQueued bool
	var notifID sql.NullInt64
	err = s.DB.QueryRowContext(ctx,
		`SELECT state = $1, notification_id FROM human_input_deliveries
		  WHERE id = $2 AND user_id = $3`, HumanInputQueued, id, userID,
	).Scan(&wasQueued, &notifID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrHumanInputDeliveryNotFound
	}
	if err != nil {
		return false, fmt.Errorf("read human input delivery state: %w", err)
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE human_input_deliveries
		    SET state = $1, last_outcome = $2, responded_at = COALESCE($3, responded_at), updated_at = $4
		  WHERE id = $5 AND user_id = $6 AND state IN ($7, $8)`,
		state, outcome, respondedAt, now, id, userID, HumanInputQueued, HumanInputSent)
	if err != nil {
		return false, fmt.Errorf("mark human input delivery: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mark human input delivery: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	if wasQueued && notifID.Valid && state != HumanInputAnswered {
		if err := s.MarkOwnerNotificationFailed(ctx, userID, notifID.Int64); err != nil && !errors.Is(err, ErrOwnerNotificationNotFound) {
			return true, fmt.Errorf("retire queued human input notification: %w", err)
		}
	}
	return true, nil
}

// SupersedeHumanInputDeliveries marks the user's open rows for requestID whose
// hash differs from keepHash as superseded and returns how many changed.
func (s *Store) SupersedeHumanInputDeliveries(ctx context.Context, userID int64, requestID, keepHash string) (int, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id FROM human_input_deliveries
		  WHERE user_id = $1 AND request_id = $2 AND request_hash <> $3 AND state IN ($4, $5)`,
		userID, requestID, keepHash, HumanInputQueued, HumanInputSent)
	if err != nil {
		return 0, fmt.Errorf("find superseded human input deliveries: %w", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan superseded human input delivery: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()
	changedCount := 0
	for _, id := range ids {
		changed, err := s.MarkHumanInputDelivery(ctx, userID, id, HumanInputSuperseded, "superseded")
		if err != nil {
			return changedCount, err
		}
		if changed {
			changedCount++
		}
	}
	return changedCount, nil
}

// SetHumanInputDeliveryMessageID records the Telegram message id of a delivered
// notification and moves its row queued -> sent. It returns the row's
// created_at so the notifier can observe delivery latency; found=false means
// the notification has no (still queued) human-input row (e.g. a follow-up).
func (s *Store) SetHumanInputDeliveryMessageID(ctx context.Context, notificationID, tgMessageID int64) (createdAt time.Time, found bool, err error) {
	now := time.Now().UTC()
	err = s.DB.QueryRowContext(ctx,
		`UPDATE human_input_deliveries
		    SET tg_message_id = $1, state = $2, delivered_at = $3, updated_at = $3
		  WHERE notification_id = $4 AND state = $5
		  RETURNING created_at`,
		tgMessageID, HumanInputSent, now, notificationID, HumanInputQueued,
	).Scan(&createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("set human input message id: %w", err)
	}
	return createdAt, true, nil
}

// HumanInputActor is a polling hint: a user the poller should ask mctl-api
// about. It is NOT authorization — mctl-api decides eligibility per call.
type HumanInputActor struct {
	UserID       int64
	TGID         int64
	DormantUntil time.Time
	FailCount    int
}

// UpsertHumanInputActor enrolls (or refreshes) a user as a polling candidate
// and clears any dormancy: a fresh successful relay call means the link works.
func (s *Store) UpsertHumanInputActor(ctx context.Context, userID, tgID int64) error {
	if userID <= 0 || tgID <= 0 {
		return errors.New("user id and telegram id must be positive")
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO human_input_actors(user_id, tg_id, dormant_until, fail_count, last_error, updated_at)
		 VALUES($1,$2,NULL,0,'',$3)
		 ON CONFLICT(user_id) DO UPDATE SET
		     tg_id = excluded.tg_id, dormant_until = NULL, fail_count = 0, last_error = '', updated_at = excluded.updated_at`,
		userID, tgID, time.Now().UTC()); err != nil {
		return fmt.Errorf("upsert human input actor: %w", err)
	}
	return nil
}

// MarkHumanInputActorDormant records a failed poll (a 403 link_* answer) and
// suspends polling until now+backoff, doubling from base up to max with each
// consecutive failure. It only stops wasted polling; it decides nothing about
// authorization.
func (s *Store) MarkHumanInputActorDormant(ctx context.Context, userID int64, errClass string, base, max time.Duration) error {
	var failCount int
	err := s.DB.QueryRowContext(ctx, `SELECT fail_count FROM human_input_actors WHERE user_id = $1`, userID).Scan(&failCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read human input actor: %w", err)
	}
	failCount++
	backoff := base
	for i := 1; i < failCount && backoff < max; i++ {
		backoff *= 2
	}
	if backoff > max {
		backoff = max
	}
	now := time.Now().UTC()
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE human_input_actors SET dormant_until = $1, fail_count = $2, last_error = $3, updated_at = $4
		  WHERE user_id = $5`,
		now.Add(backoff), failCount, errClass, now, userID); err != nil {
		return fmt.Errorf("mark human input actor dormant: %w", err)
	}
	return nil
}

// ListPollableHumanInputActors returns enrolled actors that are not dormant at
// now.
func (s *Store) ListPollableHumanInputActors(ctx context.Context, now time.Time) ([]HumanInputActor, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT user_id, tg_id, dormant_until, fail_count FROM human_input_actors
		  WHERE dormant_until IS NULL OR dormant_until <= $1 ORDER BY user_id`, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("list human input actors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []HumanInputActor
	for rows.Next() {
		var a HumanInputActor
		var dormant sql.NullTime
		if err := rows.Scan(&a.UserID, &a.TGID, &dormant, &a.FailCount); err != nil {
			return nil, fmt.Errorf("scan human input actor: %w", err)
		}
		if dormant.Valid {
			a.DormantUntil = dormant.Time
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// BackfillHumanInputActorsFromBindings enrolls every user that already has a
// work_item_bindings row (and a known Telegram login id) as a polling
// candidate. Idempotent; existing actor rows are left untouched. Returns the
// number of rows inserted.
func (s *Store) BackfillHumanInputActorsFromBindings(ctx context.Context) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO human_input_actors(user_id, tg_id, dormant_until, fail_count, last_error, updated_at)
		 SELECT DISTINCT u.id, u.telegram_login_id, NULL, 0, '', $1
		   FROM work_item_bindings b JOIN users u ON u.id = b.user_id
		  WHERE u.telegram_login_id IS NOT NULL AND u.telegram_login_id > 0
		 ON CONFLICT(user_id) DO NOTHING`, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("backfill human input actors: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("backfill human input actors: %w", err)
	}
	return n, nil
}

// WorkItemExternalKey returns the external_key (normalised issue URL) of the
// user's binding for workItemID, so a delivered request can show a readable
// work ref. found=false when the user has no such binding.
func (s *Store) WorkItemExternalKey(ctx context.Context, userID int64, workItemID string) (string, bool, error) {
	var key string
	err := s.DB.QueryRowContext(ctx,
		`SELECT external_key FROM work_item_bindings
		  WHERE user_id = $1 AND work_item_id = $2 ORDER BY updated_at DESC, id DESC LIMIT 1`,
		userID, workItemID).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("work item external key: %w", err)
	}
	return key, true, nil
}
