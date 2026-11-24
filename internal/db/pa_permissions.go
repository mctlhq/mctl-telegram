package db

// pa_permissions.go stores the Personal Assistant's standing permissions
// (#1320 slice P2-S10; threat model T7 "Standing permissions", S2-A8,
// S2-A9).
//
// A row is bound to its principal, one connection and that connection's
// authority revision. It stops counting in three independent ways, and a
// reader needs all three to hold:
//   - revoked_at_ms is set: by /permissions, by any change of the
//     connection's revision, in the transaction of that change
//     (revokePAPermissionsOfConnTx), or by a consent withdrawal, /forget
//     or an admin disable of the principal
//     (revokePAPermissionsOfPrincipalTx);
//   - the revision it was granted at is not the revision asked for;
//   - expires_at_ms is not after now.
//
// InsertPAPermission is the only statement that creates a row, and the
// /permissions confirmation is its only caller
// (TestS2A8_GrantInsertHasOneCaller in internal/pa). A failed read wraps
// permissions.ErrUnreadable and is never an empty list (I9).
//
// LookupPAPermissions and PAPermissionIn are the reads of lowering
// (P2-S11): the first when a call is decided, the second inside the write
// executor's pre-dispatch transaction. No deployed wiring reaches either,
// or the insert.
//
// Timestamps are unix milliseconds, as in pa_connections.go.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// paPermissionsSchema returns the DDL of pa_permissions. device_ids is the
// canonical JSON array of permissions.EncodeDevices; ceiling is
// permissions.NoCeiling for a permission without one.
func paPermissionsSchema(pg bool) []string {
	intT := "INTEGER"
	if pg {
		intT = "BIGINT"
	}
	return []string{
		`CREATE TABLE IF NOT EXISTS pa_permissions (
			principal ` + intT + ` NOT NULL,
			id TEXT NOT NULL,
			connection_id TEXT NOT NULL,
			authority_revision ` + intT + ` NOT NULL,
			server TEXT NOT NULL,
			tool TEXT NOT NULL,
			device_ids TEXT NOT NULL,
			ceiling ` + intT + ` NOT NULL,
			created_at_ms ` + intT + ` NOT NULL,
			expires_at_ms ` + intT + ` NOT NULL,
			revoked_at_ms ` + intT + ` NOT NULL DEFAULT 0,
			PRIMARY KEY (principal, id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_permissions_connection ON pa_permissions(principal, connection_id, revoked_at_ms)`,
	}
}

func migratePAPermissions(ctx context.Context, dbConn migrateDB, pg bool) error {
	for _, s := range paPermissionsSchema(pg) {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate pa permissions: %w", err)
		}
	}
	return nil
}

func permissionUnreadable(op string, err error) error {
	return fmt.Errorf("%w: %s: %v", permissions.ErrUnreadable, op, err)
}

const paPermissionCols = `p.principal, p.id, p.connection_id, p.authority_revision, p.server, p.tool,
	p.device_ids, p.ceiling, p.created_at_ms, p.expires_at_ms, p.revoked_at_ms`

func scanPAPermission(r paRowScanner) (permissions.Permission, error) {
	var (
		p                         permissions.Permission
		devices                   string
		created, expires, revoked int64
	)
	if err := r.Scan(&p.Principal, &p.ID, &p.ConnectionID, &p.AuthorityRevision, &p.Server, &p.Tool,
		&devices, &p.Ceiling, &created, &expires, &revoked); err != nil {
		return permissions.Permission{}, err
	}
	ids, err := permissions.DecodeDevices(devices)
	if err != nil {
		return permissions.Permission{}, err
	}
	p.DeviceIDs = ids
	p.CreatedAt = time.UnixMilli(created).UTC()
	p.ExpiresAt = time.UnixMilli(expires).UTC()
	if revoked != 0 {
		p.RevokedAt = time.UnixMilli(revoked).UTC()
	}
	return p, nil
}

// InsertPAPermission creates the standing permission p in tx, the
// transaction of the update that confirmed it. p.Principal is the
// principal who pressed the confirmation.
//
// It refuses, with a permissions.Refusal and no row:
//   - a tool the threat model makes never lowerable, whatever the caller
//     checked (a second barrier behind permissions.CheckTool);
//   - an expiry not after now, or more than permissions.MaxTTL after it;
//   - a device list that is empty, too long or not canonical;
//   - a connection that is not this principal's, not active, on another
//     server, or no longer at p.AuthorityRevision: the check and the insert
//     are one statement, so a revision bump cannot fall between them;
//   - a principal already at permissions.MaxActive active permissions.
//
// Any other error is a failed write or read and says nothing about p.
func (s *Store) InsertPAPermission(ctx context.Context, tx *sql.Tx, p permissions.Permission, now time.Time) error {
	if tx == nil || p.Principal <= 0 || !permissions.ValidID(p.ID) {
		return fmt.Errorf("%w: permission", permissions.ErrInvalid)
	}
	if catalog.IsNeverLowerable(p.Tool) {
		return permissions.Refuse(permissions.ReasonNeverLowerable)
	}
	nowMS := now.UnixMilli()
	if err := permissions.CheckShape(permissions.Proposal{
		ConnectionID: p.ConnectionID, AuthorityRevision: p.AuthorityRevision, Server: p.Server, Tool: p.Tool,
		DeviceIDs: p.DeviceIDs, Ceiling: p.Ceiling, ExpiresAtMS: p.ExpiresAt.UnixMilli(),
	}, now); err != nil {
		return err
	}
	devices, err := permissions.EncodeDevices(p.DeviceIDs)
	if err != nil {
		return err
	}
	var active int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pa_permissions WHERE principal = $1 AND revoked_at_ms = 0 AND expires_at_ms > $2`,
		p.Principal, nowMS).Scan(&active); err != nil {
		return permissionUnreadable("count active", err)
	}
	if active >= permissions.MaxActive {
		return permissions.Refuse(permissions.ReasonTooMany)
	}
	// The connection row is locked until this transaction ends, by an
	// update that changes nothing: on Postgres a transition that does not
	// hold the principal lock (the refresh flight) cannot commit between
	// the read below and this insert becoming visible, so its revocation
	// always sees the new row. No dialect probe is needed, and on SQLite
	// the statement is a no-op under the write lock the transaction holds.
	held, err := tx.ExecContext(ctx,
		`UPDATE pa_connections SET authority_revision = authority_revision
		  WHERE principal = $1 AND id = $2 AND state = $3 AND authority_revision = $4 AND server = $5`,
		p.Principal, p.ConnectionID, string(connection.StateActive), p.AuthorityRevision, p.Server)
	if err != nil {
		return fmt.Errorf("insert pa permission: lock connection: %w", err)
	}
	if n, err := held.RowsAffected(); err != nil {
		return fmt.Errorf("insert pa permission: lock connection: rows affected: %w", err)
	} else if n != 1 {
		return permissions.Refuse(permissions.ReasonConnectionChange)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO pa_permissions(principal, id, connection_id, authority_revision, server, tool, device_ids,
			ceiling, created_at_ms, expires_at_ms, revoked_at_ms)
		 SELECT $1, $2, cn.id, cn.authority_revision, cn.server, $3, $4, $5, $6, $7, 0
		   FROM pa_connections cn
		  WHERE cn.principal = $1 AND cn.id = $8 AND cn.state = $9 AND cn.authority_revision = $10 AND cn.server = $11`,
		p.Principal, p.ID, p.Tool, devices, p.Ceiling, nowMS, p.ExpiresAt.UnixMilli(),
		p.ConnectionID, string(connection.StateActive), p.AuthorityRevision, p.Server)
	if err != nil {
		return fmt.Errorf("insert pa permission: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("insert pa permission: rows affected: %w", err)
	}
	if n != 1 {
		return permissions.Refuse(permissions.ReasonConnectionChange)
	}
	return nil
}

// ListActivePAPermissions returns principal's permissions that still
// count at now: not revoked, not expired, and granted at the revision their
// connection, still active, has now. Oldest first. A failed read, or a row
// that does not decode, is an error wrapping permissions.ErrUnreadable:
// never an empty or shorter list (I9).
func (s *Store) ListActivePAPermissions(ctx context.Context, principal int64, now time.Time) ([]permissions.Permission, error) {
	if principal <= 0 {
		return nil, fmt.Errorf("%w: principal", permissions.ErrInvalid)
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+paPermissionCols+`
		  FROM pa_permissions p
		  JOIN pa_connections cn ON cn.principal = p.principal AND cn.id = p.connection_id
		 WHERE p.principal = $1 AND p.revoked_at_ms = 0 AND p.expires_at_ms > $2
		   AND cn.state = $3 AND cn.authority_revision = p.authority_revision
		 ORDER BY p.created_at_ms, p.id`,
		principal, now.UnixMilli(), string(connection.StateActive))
	if err != nil {
		return nil, permissionUnreadable("list active", err)
	}
	defer func() { _ = rows.Close() }()
	out := []permissions.Permission{}
	for rows.Next() {
		p, err := scanPAPermission(rows)
		if err != nil {
			return nil, permissionUnreadable("list active: scan", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, permissionUnreadable("list active", err)
	}
	return out, nil
}

// LookupPAPermissions returns the permissions that cover tool on the
// connection at exactly revision, the revision the caller just read from
// the connection (I4), and whose expiry is after now. A permission granted
// at any other revision, an expired one and a revoked one are not
// returned. A failed read is an error, never "no permission" (I9).
//
// It is the read the card emitter makes before the gate decides
// (connector.Cards, P2-S11).
func (s *Store) LookupPAPermissions(ctx context.Context, principal int64, connectionID string, revision int64, server, tool string, now time.Time) ([]permissions.Permission, error) {
	if principal <= 0 || connectionID == "" || revision <= 0 || server == "" || tool == "" {
		return nil, fmt.Errorf("%w: permission lookup", permissions.ErrInvalid)
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+paPermissionCols+`
		  FROM pa_permissions p
		 WHERE p.principal = $1 AND p.connection_id = $2 AND p.server = $3 AND p.tool = $4
		   AND p.revoked_at_ms = 0 AND p.authority_revision = $5 AND p.expires_at_ms > $6
		 ORDER BY p.created_at_ms, p.id`,
		principal, connectionID, server, tool, revision, now.UnixMilli())
	if err != nil {
		return nil, permissionUnreadable("lookup", err)
	}
	defer func() { _ = rows.Close() }()
	out := []permissions.Permission{}
	for rows.Next() {
		p, err := scanPAPermission(rows)
		if err != nil {
			return nil, permissionUnreadable("lookup: scan", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, permissionUnreadable("lookup", err)
	}
	return out, nil
}

// PAPermissionIn reads principal's permission id inside tx, the write
// executor's pre-dispatch transaction, and keeps the row still until tx
// ends. On Postgres that is SELECT ... FOR UPDATE: a revocation either
// committed before the read, and is what it returns, or waits for tx. On
// SQLite the writer lock tx holds does the same. The row is returned as it
// is, revoked, expired or granted at another revision included; the caller
// decides with permissions.Permission.Covers. permissions.ErrNotFound: no
// such row of this principal. Any other error is a failed read and never
// "no permission" (I9).
func (s *Store) PAPermissionIn(ctx context.Context, tx *sql.Tx, principal int64, id string) (permissions.Permission, error) {
	if tx == nil || principal <= 0 || !permissions.ValidID(id) {
		return permissions.Permission{}, fmt.Errorf("%w: permission", permissions.ErrInvalid)
	}
	pg, err := s.postgresDialect(ctx)
	if err != nil {
		return permissions.Permission{}, permissionUnreadable("read in transaction: dialect", err)
	}
	lock := ""
	if pg {
		lock = " FOR UPDATE"
	}
	p, err := scanPAPermission(tx.QueryRowContext(ctx,
		`SELECT `+paPermissionCols+` FROM pa_permissions p WHERE p.principal = $1 AND p.id = $2`+lock,
		principal, id))
	if errors.Is(err, sql.ErrNoRows) {
		return permissions.Permission{}, permissions.ErrNotFound
	}
	if err != nil {
		return permissions.Permission{}, permissionUnreadable("read in transaction", err)
	}
	return p, nil
}

// RevokePAPermission revokes principal's permission id in tx.
// permissions.ErrNotFound: no such permission of this principal that is
// not already revoked.
func (s *Store) RevokePAPermission(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) error {
	if tx == nil || principal <= 0 || !permissions.ValidID(id) {
		return fmt.Errorf("%w: permission", permissions.ErrInvalid)
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE pa_permissions SET revoked_at_ms = $1 WHERE principal = $2 AND id = $3 AND revoked_at_ms = 0`,
		paRevokedAtMS(now.UnixMilli()), principal, id)
	if err != nil {
		return fmt.Errorf("revoke pa permission: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke pa permission: rows affected: %w", err)
	}
	if n != 1 {
		return permissions.ErrNotFound
	}
	return nil
}

// paRevokedAtMS keeps a revocation mark from being 0, which means "not
// revoked".
func paRevokedAtMS(nowMS int64) int64 {
	if nowMS <= 0 {
		return 1
	}
	return nowMS
}

// revokePAPermissionsOfConnTx revokes, in tx, every permission bound to the
// connection. Every statement that changes a connection's authority
// revision calls it in the transaction of that change (threat model T7:
// "revoked automatically by /disconnect or by any revision change"), so a
// permission never outlives the revision it was granted at, even for a
// reader that forgot the revision predicate. A failure fails the change.
func revokePAPermissionsOfConnTx(ctx context.Context, tx *sql.Tx, principal int64, connectionID string, nowMS int64) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_permissions SET revoked_at_ms = $1
		  WHERE principal = $2 AND connection_id = $3 AND revoked_at_ms = 0`,
		paRevokedAtMS(nowMS), principal, connectionID); err != nil {
		return fmt.Errorf("pa connection: revoke standing permissions: %w", err)
	}
	return nil
}

// revokePAPermissionsOfPrincipalTx revokes, in tx, every standing
// permission of principal, on all of its connections (#1320 slice P2-S12).
// A consent withdrawal, /forget and an admin disable call it in the
// transaction of that change: none of them moves a connection's revision,
// so without it the permissions would be in force again the moment consent
// is given again or the disable is cleared. A failure fails the change.
func revokePAPermissionsOfPrincipalTx(ctx context.Context, tx *sql.Tx, principal int64, nowMS int64) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_permissions SET revoked_at_ms = $1 WHERE principal = $2 AND revoked_at_ms = 0`,
		paRevokedAtMS(nowMS), principal); err != nil {
		return fmt.Errorf("pa principal: revoke standing permissions: %w", err)
	}
	return nil
}

// ActivePAConnectionRefs lists principal's active connections as a grant
// binds them. A failed read is an error, never "no connection".
func (s *Store) ActivePAConnectionRefs(ctx context.Context, principal int64) ([]permissions.ConnectionRef, error) {
	conns, err := s.ListPAConnections(ctx, principal)
	if err != nil {
		return nil, permissionUnreadable("connections", err)
	}
	var out []permissions.ConnectionRef
	for _, c := range conns {
		if c.State == connection.StateActive {
			out = append(out, permissions.ConnectionRef{ID: c.ID, Server: string(c.Server), AuthorityRevision: c.AuthorityRevision})
		}
	}
	return out, nil
}

// IssuePAPermissionCallback stores the callback of a /permissions screen
// for principal, in a transaction of its own: the screen is built after
// the command's update committed, because validating a grant reads the
// devices from the server. Only a /permissions action is accepted.
func (s *Store) IssuePAPermissionCallback(ctx context.Context, principal int64, id, action string, expiresAt time.Time) error {
	if !permissions.IsAction(action) {
		return fmt.Errorf("%w: not a permissions action", permissions.ErrInvalid)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("pa permission callback: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.CreatePACallback(ctx, tx, principal, id, action, expiresAt); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("pa permission callback: commit: %w", err)
	}
	return nil
}
