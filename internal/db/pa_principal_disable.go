package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mctlhq/mctl-telegram/internal/pa/auditevent"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
)

// Per-principal admin disable of the Personal Assistant (threat model T11,
// S1-F4; #1318 slice A1).
//
// pa_principal_disables holds one row per disabled principal: when, by
// which admin (the admin's users.id), and a short operator reason. It is created
// by migratePAConvo (paConvoSchema) and is deliberately NOT one of
// paPrincipalPurges: like pa_usage, a disable must survive the account's
// deletion, or deleting the account and coming back would clear it. The
// row carries ids, a timestamp and the operator's reason, no user content,
// and only ClearPAPrincipalDisabled deletes it.

// MaxPAPrincipalDisableReason bounds the reason an admin records with a
// disable, in characters.
const MaxPAPrincipalDisableReason = 200

// ErrPADisableReason refuses an empty, over-long or multi-line reason.
var ErrPADisableReason = errors.New("pa principal disable: reason must be 1-200 characters on one line")

// SetPAPrincipalDisabled disables principal's PA (an upsert: disabling a
// disabled principal records the new admin, reason and time).
func (s *Store) SetPAPrincipalDisabled(ctx context.Context, principal, by int64, reason string, now time.Time) error {
	if principal <= 0 || by <= 0 {
		return fmt.Errorf("%w: principal disable", convo.ErrInvalid)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || utf8.RuneCountInString(reason) > MaxPAPrincipalDisableReason || strings.ContainsAny(reason, "\r\n") {
		return ErrPADisableReason
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set pa principal disabled: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// The principal's lock, first: every transaction that creates an
	// approval or grants a permission holds it (BeginPAWrite, the webhook
	// update), so one that is still open commits before the cancellation
	// and the revocation below run and is seen by them, and one that
	// starts later waits and reads the disable (S2-C9). Without the lock
	// an approval committed by a concurrent transaction stayed pending,
	// with no "cancelled" card and no notice.
	if err := s.LockPAPrincipal(ctx, tx, principal); err != nil {
		return fmt.Errorf("set pa principal disabled: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pa_principal_disables(principal, disabled_at_ms, disabled_by, reason) VALUES($1, $2, $3, $4)
		 ON CONFLICT (principal) DO UPDATE SET disabled_at_ms = excluded.disabled_at_ms,
		   disabled_by = excluded.disabled_by, reason = excluded.reason`,
		principal, now.UnixMilli(), by, reason); err != nil {
		return fmt.Errorf("set pa principal disabled: %w", err)
	}
	// A refused principal is answered once per rate window, on its first
	// update (conversation.go). Resetting the window here makes the next
	// update the first, so a principal disabled mid-window is told at once
	// instead of up to a window later.
	if _, err := tx.ExecContext(ctx, `DELETE FROM pa_rate WHERE principal = $1`, principal); err != nil {
		return fmt.Errorf("set pa principal disabled: reset rate window: %w", err)
	}
	// What the principal was asked to approve, or approved and was not
	// sent yet, is cancelled on every connection, and the standing
	// permissions are revoked, in the transaction that records the disable
	// (#1320 slice P2-S12): the dispatch already refuses a disabled
	// principal, and this ends the cards and keeps a later re-enable from
	// bringing a permission back. The principal gets one notice when an
	// approval was cancelled. A failure here fails the disable.
	if _, err := cancelPAApprovalsWithNotice(ctx, tx, principal, now.UnixMilli(), "", auditevent.ReasonPrincipalDisabled); err != nil {
		return fmt.Errorf("set pa principal disabled: %w", err)
	}
	if err := revokePAPermissionsOfPrincipalTx(ctx, tx, principal, now.UnixMilli(), auditevent.ReasonPrincipalDisabled); err != nil {
		return fmt.Errorf("set pa principal disabled: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("set pa principal disabled: commit: %w", err)
	}
	return nil
}

// ClearPAPrincipalDisabled re-enables principal. Clearing a principal that
// is not disabled is not an error.
func (s *Store) ClearPAPrincipalDisabled(ctx context.Context, principal int64) error {
	if principal <= 0 {
		return fmt.Errorf("%w: principal disable", convo.ErrInvalid)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("clear pa principal disabled: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM pa_principal_disables WHERE principal = $1`, principal); err != nil {
		return fmt.Errorf("clear pa principal disabled: %w", err)
	}
	// Refused updates count in the window too, so a principal who kept
	// writing while disabled would come back already limited. Resetting it
	// here, as SetPAPrincipalDisabled does, starts them on a fresh window.
	if _, err := tx.ExecContext(ctx, `DELETE FROM pa_rate WHERE principal = $1`, principal); err != nil {
		return fmt.Errorf("clear pa principal disabled: reset rate window: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("clear pa principal disabled: commit: %w", err)
	}
	return nil
}

// PAPrincipalDisabled implements convo.Store: it reads the disable inside
// tx (the update's or the run step's transaction). Only an absent row is
// "not disabled"; every other failure is an error wrapping
// convo.ErrUnreadable, and convo.ErrStoreFault when the read itself failed.
func (s *Store) PAPrincipalDisabled(ctx context.Context, tx *sql.Tx, principal int64) (bool, error) {
	if tx == nil || principal <= 0 {
		return true, fmt.Errorf("%w: principal disable", convo.ErrInvalid)
	}
	return paPrincipalDisabled(ctx, tx, principal)
}

// PAPrincipalDisabledState reads the disable outside any transaction (the
// gate's PrincipalStatus, the admin read tool).
func (s *Store) PAPrincipalDisabledState(ctx context.Context, principal int64) (bool, error) {
	if principal <= 0 {
		return true, fmt.Errorf("%w: principal disable", convo.ErrInvalid)
	}
	return paPrincipalDisabled(ctx, s.DB, principal)
}

// paPrincipalDisabled returns true with any error: a caller that ignores
// the error still refuses.
func paPrincipalDisabled(ctx context.Context, q paQuerier, principal int64) (bool, error) {
	var at int64
	err := q.QueryRowContext(ctx, `SELECT disabled_at_ms FROM pa_principal_disables WHERE principal = $1`, principal).Scan(&at)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return true, rowRead("principal disable", err)
	}
	return true, nil
}
