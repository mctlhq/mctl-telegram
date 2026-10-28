package mcp

import (
	"context"
	"errors"
	"log/slog"

	gotdtelegram "github.com/gotd/td/telegram"
	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/sanitize"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// sponsoredToolGuidance is the paragraph get_messages and get_unread_messages
// carry in their descriptions. Telegram's API terms (§3.3) require an app
// that shows channel posts to show the channel's official sponsored
// messages, so the model is told how to present them.
const sponsoredToolGuidance = `Broadcast channels: when the result holds posts from a broadcast channel, the "sponsored" field lists the official Telegram sponsored messages served for that channel ({label, channel, title, text, url, button_text, sponsor_info, additional_info, random_id}). They are ADVERTISING, not channel content, and are never mixed into "messages". Whenever you show or summarise that channel's posts to the user, also show each of its sponsored items verbatim (title, text, url and button_text as given), clearly labelled with its label ("Sponsored" or "Recommended"), after the channel's posts. random_id is only an identifier; do not show it. "sponsored_unavailable" lists channels whose sponsored messages could not be fetched: that is unknown, not "no ads", so tell the user the channel's sponsored messages could not be loaded. The server operator can switch broadcast channel content off; a broadcast channel is then refused, and an unscoped get_unread_messages skips channels.`

// wrapSponsored returns a sanitized copy of msgs. Item text is untrusted
// third-party content, so it is wrapped like a message body. The fields are
// cleaned but not otherwise rewritten: the model must show them verbatim.
func wrapSponsored(msgs []telegram.SponsoredMessage) []telegram.SponsoredMessage {
	if len(msgs) == 0 {
		return nil
	}
	out := make([]telegram.SponsoredMessage, len(msgs))
	for i, m := range msgs {
		if m.Text != "" {
			m.Text = WrapUntrustedContent(sanitize.UserContent(m.Text, 4096), telegram.RedactPeer(m.Channel))
		}
		m.Title = sanitizeOptional(m.Title, 256)
		m.URL = sanitizeOptional(m.URL, 2048)
		m.ButtonText = sanitizeOptional(m.ButtonText, 128)
		m.SponsorInfo = sanitizeOptional(m.SponsorInfo, 1024)
		m.AdditionalInfo = sanitizeOptional(m.AdditionalInfo, 1024)
		out[i] = m
	}
	return out
}

// sanitizeOptional cleans s, keeping an empty value empty so the "[empty]"
// sentinel never reaches the output.
func sanitizeOptional(s string, max int) string {
	if s == "" {
		return s
	}
	return sanitize.UserContent(s, max)
}

// attachSponsored copies sp into result and counts it. A nil sp (no
// broadcast channel post was read) leaves both fields absent.
func (s *Server) attachSponsored(tool string, result *messagesResult, sp *telegram.Sponsored) {
	if sp == nil {
		return
	}
	result.Sponsored = wrapSponsored(sp.Messages)
	result.SponsoredUnavailable = sp.Unavailable
	if s.Metrics != nil {
		s.Metrics.TelegramSponsoredTotal.WithLabelValues(tool, "returned").Add(float64(len(sp.Messages)))
		s.Metrics.TelegramSponsoredTotal.WithLabelValues(tool, "unavailable").Add(float64(len(sp.Unavailable)))
	}
}

// sponsoredViewReporter sends the messages.viewSponsoredMessage calls for
// msgs and returns the items whose report failed (all of them when no client
// could be borrowed). Production code borrows a pooled client; tests that
// reassign this package variable must restore it via t.Cleanup.
var sponsoredViewReporter = func(s *Server, ctx context.Context, userID int64, msgs []telegram.SponsoredMessage) ([]telegram.SponsoredMessage, error) {
	if s.Pool == nil {
		return msgs, errors.New("no client pool")
	}
	failed := msgs
	err := s.Pool.Borrow(ctx, userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		failed = telegram.ReportSponsoredViews(ctx, c, msgs)
		return nil
	})
	return failed, err
}

// reportSponsoredViews reports a view of each sponsored item in sp, but only
// when res is a successful result: the items were then returned to the
// caller. A failed result reports nothing. An item whose view was reported
// for this user within telegram.SponsoredViewTTL is not reported again, so
// paging or re-reading a channel counts its ads once (issue #906); an item
// whose report failed is released and reported on the next read. Reporting
// never changes res; a failure is logged and counted.
func (s *Server) reportSponsoredViews(ctx context.Context, tool string, userID int64, sp *telegram.Sponsored, res *mcplib.CallToolResult) {
	if sp == nil || len(sp.Messages) == 0 || res == nil || res.IsError {
		return
	}
	due, claim := s.sponsoredViews.Claim(userID, sp.Messages)
	if s.Metrics != nil {
		s.Metrics.TelegramSponsoredTotal.WithLabelValues(tool, "view_deduplicated").Add(float64(len(sp.Messages) - len(due)))
	}
	if len(due) == 0 {
		return
	}
	failed, err := sponsoredViewReporter(s, ctx, userID, due)
	s.sponsoredViews.Release(userID, claim, failed)
	if err != nil {
		slog.Warn("sponsored message views not reported", "tool", tool, "user_id", userID, "count", len(due), "err", err)
	}
	if s.Metrics != nil {
		s.Metrics.TelegramSponsoredTotal.WithLabelValues(tool, "viewed").Add(float64(len(due) - len(failed)))
		s.Metrics.TelegramSponsoredTotal.WithLabelValues(tool, "view_failed").Add(float64(len(failed)))
	}
}
