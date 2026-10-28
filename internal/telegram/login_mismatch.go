package telegram

import (
	"context"
	"log/slog"

	"github.com/gotd/td/tg"
)

// authLogOuter is the one MTProto call logOutIfMismatch needs, so tests can
// observe it without a live client.
type authLogOuter interface {
	AuthLogOut(ctx context.Context) (*tg.AuthLoggedOut, error)
}

// logOutIfMismatch logs the just-authorized account out when it is not the
// one the caller expected, and reports whether it was a mismatch. want == 0
// means the caller expects no particular account. A failed logOut is logged,
// not returned: the caller refuses the login on the id either way, and the
// revoked row keeps the session unusable on our side.
func logOutIfMismatch(ctx context.Context, api authLogOuter, userID, want, got int64) bool {
	if want == 0 || want == got {
		return false
	}
	if _, err := api.AuthLogOut(ctx); err != nil {
		slog.WarnContext(ctx, "telegram login: logout of a mismatched account failed",
			"user_id", userID, "err", err)
		return true
	}
	slog.InfoContext(ctx, "telegram login: logged out a mismatched account", "user_id", userID)
	return true
}
