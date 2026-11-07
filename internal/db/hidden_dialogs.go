package db

// hidden_dialogs.go stores the dialogs an account owner hid from every
// connected client (mctl-telegram#1152). The scope is a blocklist per
// account: a row hides one dialog, every other dialog stays visible,
// including ones that appear later. Rows are written only from the manage
// page; no MCP tool can add or remove one, so a client cannot widen what it
// sees.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MaxHiddenDialogs bounds the rows one account can hold.
const MaxHiddenDialogs = 500

// ErrTooManyHiddenDialogs is returned by HideDialog at MaxHiddenDialogs.
var ErrTooManyHiddenDialogs = errors.New("too many hidden chats")

// HiddenDialog is one hidden dialog. Title is the chat's name when it was
// hidden, kept only so the manage page can list it without a Telegram call.
type HiddenDialog struct {
	Peer  string
	Title string
}

// CanonicalDialogRef returns ref as "user:<id>", "chat:<id>" or
// "channel:<id>" with a positive id, or ok=false for anything else.
func CanonicalDialogRef(ref string) (string, bool) {
	kind, num, ok := strings.Cut(strings.TrimSpace(ref), ":")
	if !ok {
		return "", false
	}
	switch kind {
	case "user", "chat", "channel":
	default:
		return "", false
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 {
		return "", false
	}
	return kind + ":" + strconv.FormatInt(n, 10), true
}

// ListHiddenDialogs returns the user's hidden dialogs ordered by title. A
// failed read is an error, never an empty list: callers enforce the scope
// from this result and must fail closed.
func (s *Store) ListHiddenDialogs(ctx context.Context, userID int64) ([]HiddenDialog, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT peer, title FROM hidden_dialogs WHERE user_id = $1 ORDER BY title, peer`, userID)
	if err != nil {
		return nil, fmt.Errorf("list hidden dialogs: %w", err)
	}
	defer rows.Close()
	var out []HiddenDialog
	for rows.Next() {
		var h HiddenDialog
		if err := rows.Scan(&h.Peer, &h.Title); err != nil {
			return nil, fmt.Errorf("list hidden dialogs: scan: %w", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list hidden dialogs: %w", err)
	}
	return out, nil
}

// HideDialog hides peer (a canonical ref) for the user. Hiding a dialog that
// is already hidden refreshes its title and succeeds.
func (s *Store) HideDialog(ctx context.Context, userID int64, peer, title string) error {
	ref, ok := CanonicalDialogRef(peer)
	if !ok {
		return fmt.Errorf("hide dialog: %q is not a chat id", peer)
	}
	title = strings.TrimSpace(title)
	if r := []rune(title); len(r) > 256 {
		title = string(r[:256])
	}
	// One statement, so two concurrent hides cannot both pass the cap. A
	// row already present always updates; a new row inserts only while
	// the account holds fewer than MaxHiddenDialogs.
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO hidden_dialogs (user_id, peer, title, hidden_at)
		 SELECT $1, $2, $3, $4
		 WHERE EXISTS (SELECT 1 FROM hidden_dialogs WHERE user_id = $1 AND peer = $2)
		    OR (SELECT COUNT(*) FROM hidden_dialogs WHERE user_id = $1) < $5
		 ON CONFLICT (user_id, peer) DO UPDATE SET title = excluded.title`,
		userID, ref, title, time.Now().UTC(), MaxHiddenDialogs,
	)
	if err != nil {
		return fmt.Errorf("hide dialog: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("hide dialog: %w", err)
	} else if n == 0 {
		return ErrTooManyHiddenDialogs
	}
	return nil
}

// UnhideDialog makes peer visible again and reports whether a row went.
func (s *Store) UnhideDialog(ctx context.Context, userID int64, peer string) (bool, error) {
	ref, ok := CanonicalDialogRef(peer)
	if !ok {
		return false, fmt.Errorf("unhide dialog: %q is not a chat id", peer)
	}
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM hidden_dialogs WHERE user_id = $1 AND peer = $2`, userID, ref)
	if err != nil {
		return false, fmt.Errorf("unhide dialog: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// IsDialogHidden reports whether the canonical ref is hidden for the user.
// It serves paths that check one chat at a time, such as the assistant
// runtime. A failed read is an error, never "visible".
func (s *Store) IsDialogHidden(ctx context.Context, userID int64, ref string) (bool, error) {
	var n int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM hidden_dialogs WHERE user_id = $1 AND peer = $2`, userID, ref,
	).Scan(&n); err != nil {
		return false, fmt.Errorf("is dialog hidden: %w", err)
	}
	return n > 0, nil
}
