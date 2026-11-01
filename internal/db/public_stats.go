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
//
// The monitoring canary accounts (CANARY_TELEGRAM_IDS) are excluded from
// every field, the same intent as the SLI rules' traffic!="canary".
type PublicStats struct {
	// AccountsTotal is the number of users who signed in with Telegram and
	// have not deleted their account.
	AccountsTotal int64
	// ToolCallsTotal is the number of successful MCP tool invocations ever
	// recorded in audit_logs, excluding connect steps, Local Bridge keepalive
	// traffic and web form posts.
	ToolCallsTotal int64
	// ActiveUsers30d is the number of distinct users with at least one such
	// invocation in the 30 days before now.
	ActiveUsers30d int64
	// SessionsActive is the number of live Telegram sessions used within the
	// last hour (the same rule as CountActiveSessions).
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
// canaryTelegramIDs lists the Telegram ids of the monitoring canary accounts.
// A probe that runs every few minutes would otherwise be the largest "user"
// in the table, and its always-on session would pad the online count. An
// empty list excludes nobody.
//
// The ToolCallsTotal and ActiveUsers30d queries scan audit_logs (84k rows,
// 19 MB at the time of writing). They are meant to run from a timer every
// few minutes, never per request; if the table grows past what a periodic
// COUNT can afford, a partial index on (status, tool_name) or a maintained
// counter table is the upgrade path.
func (s *Store) PublicStatsQuery(ctx context.Context, canaryTelegramIDs []int64) (PublicStats, error) {
	var out PublicStats

	// The canary accounts are resolved to users.id with a subquery that takes
	// one positional placeholder per id (the same IN-list construction as
	// LastConnectStepFor; "IN ()" is a syntax error on both dialects, so the
	// clause is omitted when the list is empty). Each statement appends its
	// own extra parameter AFTER the canary ids.
	canarySub := ""
	var canaryArgs []any
	if len(canaryTelegramIDs) > 0 {
		placeholders := make([]string, len(canaryTelegramIDs))
		for i, id := range canaryTelegramIDs {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			canaryArgs = append(canaryArgs, id)
		}
		canarySub = `(SELECT id FROM users WHERE telegram_login_id IN (` + strings.Join(placeholders, ",") + `))`
	}
	notCanary := func(col string) string {
		if canarySub == "" {
			return ""
		}
		return ` AND ` + col + ` NOT IN ` + canarySub
	}
	nextPlaceholder := fmt.Sprintf("$%d", len(canaryArgs)+1)
	withExtra := func(v any) []any { return append(append([]any{}, canaryArgs...), v) }

	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users
		  WHERE telegram_login_id IS NOT NULL
		    AND account_deleted_at IS NULL`+notCanary("id"),
		canaryArgs...,
	).Scan(&out.AccountsTotal); err != nil {
		return PublicStats{}, fmt.Errorf("public stats: accounts: %w", err)
	}

	// Rows with a NULL user_id (none are written today, but the column is
	// nullable) stay counted as calls and are not attributed to anyone.
	toolCanary := ""
	if canarySub != "" {
		toolCanary = ` AND (user_id IS NULL OR user_id NOT IN ` + canarySub + `)`
	}
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE `+publicToolFilter+toolCanary,
		canaryArgs...,
	).Scan(&out.ToolCallsTotal); err != nil {
		return PublicStats{}, fmt.Errorf("public stats: tool calls: %w", err)
	}

	// The cutoff is passed as a parameter rather than computed in SQL so the
	// same statement runs on SQLite and Postgres (as CountActiveSessions
	// does).
	since := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT user_id) FROM audit_logs
		  WHERE `+publicToolFilter+`
		    AND user_id IS NOT NULL`+notCanary("user_id")+`
		    AND created_at > `+nextPlaceholder,
		withExtra(since)...,
	).Scan(&out.ActiveUsers30d); err != nil {
		return PublicStats{}, fmt.Errorf("public stats: active users: %w", err)
	}

	// Same rule as CountActiveSessions (live row, used within the hour or
	// never), minus the canary's always-on session. Kept as its own
	// statement rather than changing CountActiveSessions, whose gauge feeds
	// the SLO rules and must keep counting the canary. The canary clause
	// comes before the cutoff placeholder, as in the statement above, so the
	// placeholders appear in the text in argument order on both dialects.
	cutoff := time.Now().UTC().Add(-time.Hour)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM telegram_accounts
		  WHERE revoked_at IS NULL`+notCanary("user_id")+`
		    AND (last_used_at IS NULL OR last_used_at > `+nextPlaceholder+`)`,
		withExtra(cutoff)...,
	).Scan(&out.SessionsActive); err != nil {
		return PublicStats{}, fmt.Errorf("public stats: sessions: %w", err)
	}
	return out, nil
}
