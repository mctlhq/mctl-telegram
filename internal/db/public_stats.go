package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// PublicStats is the set of aggregate usage numbers the landing page shows.
// Every field is a count over the whole deployment; none identifies a user,
// a peer or a message, so the struct is safe to serve unauthenticated.
type PublicStats struct {
	// AccountsTotal is the number of users who signed in with Telegram and
	// have not deleted their account.
	AccountsTotal int64
	// ToolCallsTotal is the number of successful MCP tool invocations ever
	// recorded in audit_logs, excluding connect steps, Local Bridge keepalive
	// traffic, web form posts and the monitoring canary.
	ToolCallsTotal int64
	// ActiveUsers30d is the number of distinct users with at least one such
	// invocation in the 30 days before now.
	ActiveUsers30d int64
	// SessionsActive is CountActiveSessions at the time of the sample.
	SessionsActive int64
}

// publicToolFilter selects the audit rows that count as a user-visible tool
// call. connect:* rows are login steps, local_bridge_* rows are the daemon's
// keepalive (one device produced ~10k of them in a week), and "POST /..."
// rows are web form submissions recorded through the same audit path.
const publicToolFilter = `status = 'ok'
	   AND tool_name NOT LIKE 'connect%'
	   AND tool_name NOT LIKE 'local_bridge%'
	   AND tool_name NOT LIKE 'POST %'`

// PublicStatsQuery runs the aggregate queries behind PublicStats.
//
// canaryTelegramIDs lists the Telegram ids of the monitoring canary accounts
// (CANARY_TELEGRAM_IDS). Their calls are excluded from ToolCallsTotal and
// ActiveUsers30d the same way the SLI rules select traffic!="canary": a probe
// that runs every few minutes would otherwise be the largest "user" in the
// table. An empty list excludes nobody.
//
// The ToolCallsTotal and ActiveUsers30d queries scan audit_logs (84k rows,
// 19 MB at the time of writing). They are meant to run from a timer every
// few minutes, never per request; if the table grows past what a periodic
// COUNT can afford, a partial index on (status, tool_name) or a maintained
// counter table is the upgrade path.
func (s *Store) PublicStatsQuery(ctx context.Context, canaryTelegramIDs []int64) (PublicStats, error) {
	var out PublicStats

	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users
		  WHERE telegram_login_id IS NOT NULL
		    AND account_deleted_at IS NULL`,
	).Scan(&out.AccountsTotal); err != nil {
		return PublicStats{}, fmt.Errorf("public stats: accounts: %w", err)
	}

	// The canary clause is appended as a NOT IN over users.id resolved from
	// telegram_login_id, with one positional placeholder per id (the same
	// IN-list construction as LastConnectStepFor; "IN ()" is a syntax error
	// on both dialects, so the clause is omitted when the list is empty).
	canaryClause := ""
	var canaryArgs []any
	if len(canaryTelegramIDs) > 0 {
		placeholders := make([]string, len(canaryTelegramIDs))
		for i, id := range canaryTelegramIDs {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			canaryArgs = append(canaryArgs, id)
		}
		canaryClause = ` AND (user_id IS NULL OR user_id NOT IN (
			SELECT id FROM users WHERE telegram_login_id IN (` + strings.Join(placeholders, ",") + `)))`
	}

	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE `+publicToolFilter+canaryClause,
		canaryArgs...,
	).Scan(&out.ToolCallsTotal); err != nil {
		return PublicStats{}, fmt.Errorf("public stats: tool calls: %w", err)
	}

	// The cutoff is passed as a parameter rather than computed in SQL so the
	// same statement runs on SQLite and Postgres (as CountActiveSessions
	// does). It takes the placeholder after the canary ids.
	since := time.Now().UTC().Add(-30 * 24 * time.Hour)
	sinceArgs := append(append([]any{}, canaryArgs...), since)
	sincePlaceholder := fmt.Sprintf("$%d", len(canaryArgs)+1)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT user_id) FROM audit_logs
		  WHERE `+publicToolFilter+canaryClause+`
		    AND user_id IS NOT NULL
		    AND created_at > `+sincePlaceholder,
		sinceArgs...,
	).Scan(&out.ActiveUsers30d); err != nil {
		return PublicStats{}, fmt.Errorf("public stats: active users: %w", err)
	}

	n, err := s.CountActiveSessions(ctx)
	if err != nil {
		return PublicStats{}, fmt.Errorf("public stats: %w", err)
	}
	out.SessionsActive = n
	return out, nil
}
