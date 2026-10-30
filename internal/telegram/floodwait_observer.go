package telegram

import (
	"context"
	"log/slog"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// floodWaitObserver is a pooled-client middleware that records every
// FLOOD_WAIT Telegram answers with, at the one place the RPC method is still
// known. mctl_telegram_flood_wait_events_total only carries the MCP tool, so
// a slow get_messages could not be traced to messages.getHistory versus a
// username resolve, nor to the account or kind of peer that drew the limit.
//
// It only observes: the error is returned unchanged and the retry stays with
// the caller (borrowWithRetry). The peer is logged as its kind alone, never
// its id or access hash.
func floodWaitObserver(userID int64, m *metrics.Registry) telegram.Middleware {
	return telegram.MiddlewareFunc(func(next tg.Invoker) telegram.InvokeFunc {
		return func(ctx context.Context, input bin.Encoder, output bin.Decoder) error {
			err := next.Invoke(ctx, input, output)
			wait, ok := floodWait(err)
			if !ok {
				return err
			}
			method := rpcMethod(input)
			slog.Warn("telegram flood wait",
				"user_id", userID,
				"method", method,
				"peer_kind", peerKind(input),
				"wait_seconds", wait)
			if m != nil {
				m.TelegramFloodWaitSeconds.WithLabelValues(method).Observe(float64(wait))
			}
			return err
		}
	})
}

// rpcMethod names the TL request, e.g. "messages.getHistory". Every gotd
// request type has a TypeName; "unknown" covers anything that does not.
func rpcMethod(input bin.Encoder) string {
	if n, ok := input.(interface{ TypeName() string }); ok && n.TypeName() != "" {
		return n.TypeName()
	}
	return "unknown"
}

// peerKind reports the kind of peer a request targets, or "none" when it
// takes no single peer.
func peerKind(input bin.Encoder) string {
	p, ok := input.(interface{ GetPeer() tg.InputPeerClass })
	if !ok {
		return "none"
	}
	switch p.GetPeer().(type) {
	case *tg.InputPeerUser, *tg.InputPeerUserFromMessage:
		return "user"
	case *tg.InputPeerChat:
		return "chat"
	case *tg.InputPeerChannel, *tg.InputPeerChannelFromMessage:
		return "channel"
	case *tg.InputPeerSelf:
		return "self"
	default:
		return "other"
	}
}
