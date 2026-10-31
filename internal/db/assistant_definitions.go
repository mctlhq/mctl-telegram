package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Registry lifecycles of an assistant version (docs/assistants/spec.md,
// "Registry form").
const (
	AssistantLifecyclePublished  = "published"
	AssistantLifecycleDeprecated = "deprecated"
	AssistantLifecycleDisabled   = "disabled"
)

// ErrAssistantDefinitionNotFound means no snapshot is stored for a digest.
var ErrAssistantDefinitionNotFound = errors.New("assistant definition not found")

// AssistantDefinition is the durable snapshot of a registry definition an
// install pinned (#1020). Document is the canonical materialized JSON whose
// sha256 is Digest; the caller checks that before storing it.
type AssistantDefinition struct {
	Digest   string
	Name     string
	Version  string
	Document []byte
	// Lifecycle is the registry lifecycle last observed for Name@Version,
	// and LifecycleCheckedAt when it was last read successfully. A failed
	// read changes neither.
	Lifecycle          string
	FetchedAt          time.Time
	LifecycleCheckedAt time.Time
}

// InstallAgentAssistant stores def and applies u to userID's profile in one
// transaction, so an install revision never points at a definition the
// database does not hold and a stored definition is never left behind by an
// install that failed. The snapshot is idempotent by digest: storing a
// definition again only refreshes its lifecycle. u.AssistantDigest must
// name def. ErrAgentProfileNotFound if the profile row does not exist.
func (s *Store) InstallAgentAssistant(ctx context.Context, userID int64, def AssistantDefinition, u AgentProfileUpdate) error {
	if userID <= 0 {
		return errors.New("user id required")
	}
	if def.Digest == "" || len(def.Document) == 0 {
		return errors.New("assistant definition digest and document required")
	}
	if u.AssistantDigest == nil || *u.AssistantDigest != def.Digest {
		return errors.New("install must pin the stored definition's digest")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin install: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := storeAssistantDefinition(ctx, tx, def); err != nil {
		return err
	}
	if err := s.updateAgentProfileFields(ctx, tx, userID, u); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit install: %w", err)
	}
	return nil
}

// storeAssistantDefinition stores def's snapshot on ex, or only refreshes
// its lifecycle when the digest is already stored.
func storeAssistantDefinition(ctx context.Context, ex execer, def AssistantDefinition) error {
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := ex.ExecContext(ctx,
		`INSERT INTO assistant_definitions(digest, name, version, document, lifecycle, fetched_at, lifecycle_checked_at)
		 VALUES($1,$2,$3,$4,$5,$6,$6)
		 ON CONFLICT (digest) DO UPDATE SET lifecycle = EXCLUDED.lifecycle,
		        lifecycle_checked_at = EXCLUDED.lifecycle_checked_at`,
		def.Digest, def.Name, def.Version, string(def.Document), def.Lifecycle, now,
	); err != nil {
		return fmt.Errorf("store assistant definition: %w", err)
	}
	return nil
}

// GetAssistantDefinition returns the snapshot stored for digest, or
// ErrAssistantDefinitionNotFound.
func (s *Store) GetAssistantDefinition(ctx context.Context, digest string) (*AssistantDefinition, error) {
	var d AssistantDefinition
	var doc string
	err := s.DB.QueryRowContext(ctx,
		`SELECT digest, name, version, document, lifecycle, fetched_at, lifecycle_checked_at
		   FROM assistant_definitions WHERE digest = $1`,
		digest,
	).Scan(&d.Digest, &d.Name, &d.Version, &doc, &d.Lifecycle, &d.FetchedAt, &d.LifecycleCheckedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAssistantDefinitionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get assistant definition: %w", err)
	}
	d.Document = []byte(doc)
	return &d, nil
}

// ListPinnedAssistantDefinitions returns every stored definition some
// profile currently pins, directly or as the base of the fork it pins,
// without its document: the set the lifecycle refresh reads from the
// registry. A fork's lifecycle is its base's (#1043).
func (s *Store) ListPinnedAssistantDefinitions(ctx context.Context) ([]AssistantDefinition, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT d.digest, d.name, d.version, d.lifecycle, d.fetched_at, d.lifecycle_checked_at
		   FROM assistant_definitions d
		  WHERE EXISTS (SELECT 1 FROM agent_profiles p WHERE p.assistant_definition_digest = d.digest)
		     OR EXISTS (SELECT 1 FROM assistant_forks f
		                  JOIN agent_profiles p ON p.user_id = f.user_id AND p.assistant_definition_digest = f.digest
		                 WHERE f.base_digest = d.digest)
		  ORDER BY d.name, d.version, d.digest`)
	if err != nil {
		return nil, fmt.Errorf("list pinned assistant definitions: %w", err)
	}
	defer rows.Close()
	var out []AssistantDefinition
	for rows.Next() {
		var d AssistantDefinition
		if err := rows.Scan(&d.Digest, &d.Name, &d.Version, &d.Lifecycle, &d.FetchedAt, &d.LifecycleCheckedAt); err != nil {
			return nil, fmt.Errorf("scan assistant definition: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list pinned assistant definitions: %w", err)
	}
	return out, nil
}

// SetAssistantDefinitionLifecycle records a lifecycle the registry
// answered for digest's name@version at checkedAt, kept to the
// microsecond. Only a successful read
// may call it: a failed one leaves the last known lifecycle and its check
// time alone, which is what lets staleness be measured.
func (s *Store) SetAssistantDefinitionLifecycle(ctx context.Context, digest, lifecycle string, checkedAt time.Time) error {
	switch lifecycle {
	case AssistantLifecyclePublished, AssistantLifecycleDeprecated, AssistantLifecycleDisabled:
	default:
		return fmt.Errorf("unknown assistant lifecycle %q", lifecycle)
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE assistant_definitions SET lifecycle = $1, lifecycle_checked_at = $2 WHERE digest = $3`,
		lifecycle, checkedAt.UTC().Truncate(time.Microsecond), digest)
	if err != nil {
		return fmt.Errorf("set assistant definition lifecycle: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAssistantDefinitionNotFound
	}
	return nil
}

// ListListeningUsersPinnedTo returns the accounts with their listener on
// whose install pins digest, or a fork of it: the owners to tell when it
// can no longer run.
func (s *Store) ListListeningUsersPinnedTo(ctx context.Context, digest string) ([]int64, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT user_id FROM agent_profiles p
		  WHERE listener_enabled = $2
		    AND (assistant_definition_digest = $1
		         OR EXISTS (SELECT 1 FROM assistant_forks f
		                     WHERE f.user_id = p.user_id AND f.digest = p.assistant_definition_digest
		                       AND f.base_digest = $1))
		  ORDER BY user_id`,
		digest, true)
	if err != nil {
		return nil, fmt.Errorf("list users pinned to definition: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan user id: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users pinned to definition: %w", err)
	}
	return out, nil
}

// NotifyAssistantRegistryUnreachable queues body as one owner alert for
// userID, once per stale check: the profile remembers the digest and the
// last successful check it was told about, and the alert is queued in the
// same transaction that records them. Calling it again for the same outage
// is a no-op that returns false; a new successful check followed by a new
// outage, or a new install, notifies again.
func (s *Store) NotifyAssistantRegistryUnreachable(ctx context.Context, userID int64, digest string, lastChecked time.Time, body string) (bool, error) {
	if userID <= 0 {
		return false, errors.New("user id required")
	}
	if s.Crypt == nil {
		return false, errors.New("notification encryption is not configured")
	}
	// Microseconds: what Postgres keeps of a timestamp, so the key is the
	// same whether lastChecked was read back or kept in memory.
	key := digest + "@" + strconv.FormatInt(lastChecked.UnixMicro(), 10)
	sealed, err := s.Crypt.SealForUser([]byte(body), userID)
	if err != nil {
		return false, fmt.Errorf("seal notification body: %w", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin registry notice: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE agent_profiles SET assistant_registry_notice_for = $1
		  WHERE user_id = $2 AND assistant_registry_notice_for <> $1
		    AND (assistant_definition_digest = $3
		         OR EXISTS (SELECT 1 FROM assistant_forks f
		                     WHERE f.user_id = agent_profiles.user_id
		                       AND f.digest = agent_profiles.assistant_definition_digest
		                       AND f.base_digest = $3))`,
		key, userID, digest)
	if err != nil {
		return false, fmt.Errorf("mark registry notice: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO owner_notifications(user_id, kind, body_encrypted, status) VALUES($1,$2,$3,$4)`,
		userID, NotificationAlert, sealed, NotificationPending,
	); err != nil {
		return false, fmt.Errorf("insert registry notice: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit registry notice: %w", err)
	}
	return true, nil
}
