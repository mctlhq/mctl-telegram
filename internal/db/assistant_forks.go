package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Private forks of catalog assistants (#1043, docs/assistants/adr-forks.md).
// Every read here is scoped by user_id; nothing reads a fork by name alone
// or across accounts.

// Fork quotas. A write past either is refused with ErrForkLimit and
// changes nothing.
const (
	MaxForksPerAccount = 10
	MaxVersionsPerFork = 50
)

// ForkPromotionObserve is a fork version's state until P4.3 promotes it: it
// runs in observe mode only.
const ForkPromotionObserve = "observe"

var (
	// ErrAssistantForkNotFound means the account has no such fork version.
	ErrAssistantForkNotFound = errors.New("assistant fork not found")
	// ErrForkLimit means a quota refused the write.
	ErrForkLimit = errors.New("fork_limit")
	// ErrForkConflict means the fork moved while the write was prepared: a
	// new fork whose name is taken, or an edit of a version that is no
	// longer the latest.
	ErrForkConflict = errors.New("fork changed concurrently")
	// ErrForkInUse means the delete would remove the version the account's
	// install pins.
	ErrForkInUse = errors.New("fork_in_use")
)

// IsForkAssistant reports whether an assistant name is a fork's
// (<base>~<owner-scope>~<slug>); a catalog name never holds "~".
func IsForkAssistant(name string) bool { return strings.Contains(name, "~") }

// AssistantFork is one immutable fork version. Document is the canonical
// materialized definition, plaintext at this boundary and sealed with the
// owner's key at rest; list reads leave it nil.
type AssistantFork struct {
	UserID      int64
	Name        string
	Version     string
	Digest      string
	BaseName    string
	BaseVersion string
	BaseDigest  string
	Document    []byte
	Promotion   string
	CreatedAt   time.Time
}

// ForkOwnerMAC is the server's HMAC of the account id that a fork name's
// owner scope is cut from: keyed by the server key, so the scope names an
// account without revealing its id.
func (s *Store) ForkOwnerMAC(userID int64) ([]byte, error) {
	if userID <= 0 {
		return nil, errors.New("user id required")
	}
	if s.Crypt == nil {
		return nil, errors.New("fork owner scope needs the encryption key")
	}
	return s.Crypt.BlindIndexForUser("assistant-fork-owner", []byte("assistant-fork-owner:"+strconv.FormatInt(userID, 10)), userID)
}

// beginForkTx opens a transaction holding the account's fork lock, which
// serializes the fork writes of one account (quota counts, version order,
// delete against install) on its users row. The dialect is resolved first:
// probing it inside the transaction could wait on the transaction's own
// connection, and an inconclusive probe must not silently drop the lock.
func (s *Store) beginForkTx(ctx context.Context, userID int64) (*sql.Tx, error) {
	pg, err := s.postgresDialect(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin fork write: %w", err)
	}
	q := `UPDATE users SET id = id WHERE id = $1`
	if pg {
		q = `SELECT id FROM users WHERE id = $1 FOR UPDATE`
	}
	if _, err := tx.ExecContext(ctx, q, userID); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("lock account for fork write: %w", err)
	}
	return tx, nil
}

// forkVersions lists the versions of one fork, any order.
func forkVersions(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, userID int64, name string) ([]string, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT version FROM assistant_forks WHERE user_id = $1 AND name = $2`, userID, name)
	if err != nil {
		return nil, fmt.Errorf("list fork versions: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scan fork version: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list fork versions: %w", err)
	}
	return out, nil
}

// latestForkVersion is the highest MAJOR.MINOR.PATCH in vs, "" for none.
func latestForkVersion(vs []string) string {
	latest := ""
	for _, v := range vs {
		if latest == "" || semverLess(latest, v) {
			latest = v
		}
	}
	return latest
}

func semverLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, errx := strconv.Atoi(pa[i])
		y, erry := strconv.Atoi(pb[i])
		if errx != nil || erry != nil {
			return a < b
		}
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

// InsertAssistantFork stores f as a new fork version and queues notice, if
// any, as an owner alert in the same transaction. after is the version the
// caller built f on: "" for a new fork, whose name must be free, else the
// fork's latest version, which must still be. The quotas are checked under
// the account's lock: a write past MaxForksPerAccount forks or
// MaxVersionsPerFork versions is ErrForkLimit and stores nothing.
func (s *Store) InsertAssistantFork(ctx context.Context, f AssistantFork, after, notice string) error {
	if f.UserID <= 0 {
		return errors.New("user id required")
	}
	if !IsForkAssistant(f.Name) || f.Version == "" || f.Digest == "" || f.BaseDigest == "" || len(f.Document) == 0 {
		return errors.New("fork name, version, digest, base digest and document required")
	}
	if s.Crypt == nil {
		return errors.New("fork encryption is not configured")
	}
	sealed, err := s.Crypt.SealForUser(f.Document, f.UserID)
	if err != nil {
		return fmt.Errorf("encrypt assistant fork: %w", err)
	}
	var sealedNotice []byte
	if notice != "" {
		if sealedNotice, err = s.Crypt.SealForUser([]byte(notice), f.UserID); err != nil {
			return fmt.Errorf("seal fork notice: %w", err)
		}
	}
	tx, err := s.beginForkTx(ctx, f.UserID)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	versions, err := forkVersions(ctx, tx, f.UserID, f.Name)
	if err != nil {
		return err
	}
	if latestForkVersion(versions) != after {
		return ErrForkConflict
	}
	if after == "" {
		var forks int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(DISTINCT name) FROM assistant_forks WHERE user_id = $1`, f.UserID,
		).Scan(&forks); err != nil {
			return fmt.Errorf("count forks: %w", err)
		}
		if forks >= MaxForksPerAccount {
			return ErrForkLimit
		}
	} else if len(versions) >= MaxVersionsPerFork {
		return ErrForkLimit
	}
	promotion := f.Promotion
	if promotion == "" {
		promotion = ForkPromotionObserve
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO assistant_forks(user_id, name, version, digest, base_name, base_version, base_digest,
		                             document_encrypted, promotion, created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		f.UserID, f.Name, f.Version, f.Digest, f.BaseName, f.BaseVersion, f.BaseDigest,
		sealed, promotion, time.Now().UTC().Truncate(time.Microsecond),
	); err != nil {
		return fmt.Errorf("insert assistant fork: %w", err)
	}
	if sealedNotice != nil {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO owner_notifications(user_id, kind, body_encrypted, status) VALUES($1,$2,$3,$4)`,
			f.UserID, NotificationAlert, sealedNotice, NotificationPending,
		); err != nil {
			return fmt.Errorf("insert fork notice: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit fork write: %w", err)
	}
	return nil
}

const forkColumns = `user_id, name, version, digest, base_name, base_version, base_digest, document_encrypted, promotion, created_at`

func (s *Store) scanFork(row *sql.Row, userID int64) (*AssistantFork, error) {
	var f AssistantFork
	var sealed []byte
	err := row.Scan(&f.UserID, &f.Name, &f.Version, &f.Digest, &f.BaseName, &f.BaseVersion, &f.BaseDigest,
		&sealed, &f.Promotion, &f.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAssistantForkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get assistant fork: %w", err)
	}
	if s.Crypt == nil {
		return nil, errors.New("fork encryption is not configured")
	}
	if f.Document, err = s.Crypt.OpenForUser(sealed, userID); err != nil {
		return nil, fmt.Errorf("decrypt assistant fork: %w", err)
	}
	return &f, nil
}

// GetAssistantForkByDigest returns userID's fork version with digest, the
// way an install pin resolves: by owner and digest, never by name.
func (s *Store) GetAssistantForkByDigest(ctx context.Context, userID int64, digest string) (*AssistantFork, error) {
	if userID <= 0 {
		return nil, errors.New("user id required")
	}
	return s.scanFork(s.DB.QueryRowContext(ctx,
		`SELECT `+forkColumns+` FROM assistant_forks WHERE user_id = $1 AND digest = $2`,
		userID, digest), userID)
}

// GetAssistantFork returns userID's fork name@version.
func (s *Store) GetAssistantFork(ctx context.Context, userID int64, name, version string) (*AssistantFork, error) {
	if userID <= 0 {
		return nil, errors.New("user id required")
	}
	return s.scanFork(s.DB.QueryRowContext(ctx,
		`SELECT `+forkColumns+` FROM assistant_forks WHERE user_id = $1 AND name = $2 AND version = $3`,
		userID, name, version), userID)
}

// GetLatestAssistantFork returns the highest version of userID's fork name.
func (s *Store) GetLatestAssistantFork(ctx context.Context, userID int64, name string) (*AssistantFork, error) {
	if userID <= 0 {
		return nil, errors.New("user id required")
	}
	versions, err := forkVersions(ctx, s.DB, userID, name)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, ErrAssistantForkNotFound
	}
	return s.GetAssistantFork(ctx, userID, name, latestForkVersion(versions))
}

// ListAssistantForks returns every fork version of userID, without
// documents, by name and then version.
func (s *Store) ListAssistantForks(ctx context.Context, userID int64) ([]AssistantFork, error) {
	if userID <= 0 {
		return nil, errors.New("user id required")
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT user_id, name, version, digest, base_name, base_version, base_digest, promotion, created_at
		   FROM assistant_forks WHERE user_id = $1 ORDER BY name, created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("list assistant forks: %w", err)
	}
	defer rows.Close()
	var out []AssistantFork
	for rows.Next() {
		var f AssistantFork
		if err := rows.Scan(&f.UserID, &f.Name, &f.Version, &f.Digest, &f.BaseName, &f.BaseVersion,
			&f.BaseDigest, &f.Promotion, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan assistant fork: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list assistant forks: %w", err)
	}
	return out, nil
}

// DeleteAssistantFork deletes userID's fork name@version, or every version
// of name when version is "". The version the account's install pins is
// never deleted: a delete that would remove it is ErrForkInUse and deletes
// nothing. It returns the number of versions deleted; none found is
// ErrAssistantForkNotFound.
func (s *Store) DeleteAssistantFork(ctx context.Context, userID int64, name, version string) (int, error) {
	if userID <= 0 {
		return 0, errors.New("user id required")
	}
	tx, err := s.beginForkTx(ctx, userID)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	where, args := `user_id = $1 AND name = $2`, []any{userID, name}
	if version != "" {
		where, args = where+` AND version = $3`, append(args, version)
	}
	var pinned int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM assistant_forks
		  WHERE `+where+`
		    AND digest IN (SELECT assistant_definition_digest FROM agent_profiles WHERE user_id = $1)`,
		args...).Scan(&pinned); err != nil {
		return 0, fmt.Errorf("check pinned fork: %w", err)
	}
	if pinned > 0 {
		return 0, ErrForkInUse
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM assistant_forks WHERE `+where, args...)
	if err != nil {
		return 0, fmt.Errorf("delete assistant fork: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return 0, ErrAssistantForkNotFound
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit fork delete: %w", err)
	}
	return int(n), nil
}

// InstallAgentFork applies u, an install of userID's fork with digest
// forkDigest, in one transaction under the account's fork lock: the fork
// version must still exist (a concurrent delete_fork cannot leave the pin
// pointing at nothing) and, when base is set, narrow base, whose snapshot
// is stored alongside as InstallAgentAssistant stores a catalog one.
// ErrAssistantForkNotFound if the fork version is gone.
func (s *Store) InstallAgentFork(ctx context.Context, userID int64, forkDigest string, base *AssistantDefinition, u AgentProfileUpdate) error {
	if userID <= 0 {
		return errors.New("user id required")
	}
	if u.AssistantDigest == nil || *u.AssistantDigest != forkDigest || forkDigest == "" {
		return errors.New("install must pin the fork's digest")
	}
	tx, err := s.beginForkTx(ctx, userID)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var baseDigest string
	err = tx.QueryRowContext(ctx,
		`SELECT base_digest FROM assistant_forks WHERE user_id = $1 AND digest = $2`,
		userID, forkDigest).Scan(&baseDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAssistantForkNotFound
	}
	if err != nil {
		return fmt.Errorf("check assistant fork: %w", err)
	}
	if base != nil {
		if base.Digest != baseDigest || len(base.Document) == 0 {
			return errors.New("base snapshot is not the fork's base")
		}
		if err := storeAssistantDefinition(ctx, tx, *base); err != nil {
			return err
		}
	}
	if err := s.updateAgentProfileFields(ctx, tx, userID, u); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit fork install: %w", err)
	}
	return nil
}
