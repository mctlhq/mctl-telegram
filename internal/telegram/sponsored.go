package telegram

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// Labels a sponsored message carries. Telegram asks clients to label an item
// "recommended" instead of "sponsored" when its Recommended flag is set; both
// are advertising.
const (
	SponsoredLabel   = "Sponsored"
	RecommendedLabel = "Recommended"
)

// SponsoredMessage is one official Telegram advertisement served for a
// broadcast channel (https://core.telegram.org/api/sponsored-messages). It is
// never channel content and is never mixed into a read's messages.
type SponsoredMessage struct {
	// Label is SponsoredLabel or RecommendedLabel; it must be shown with
	// the item.
	Label string `json:"label"`
	// Channel is the canonical "channel:<id>" the item was served for.
	Channel        string `json:"channel"`
	Title          string `json:"title,omitempty"`
	Text           string `json:"text"`
	URL            string `json:"url,omitempty"`
	ButtonText     string `json:"button_text,omitempty"`
	SponsorInfo    string `json:"sponsor_info,omitempty"`
	AdditionalInfo string `json:"additional_info,omitempty"`
	// RandomID is Telegram's id for the item, standard base64. It is needed
	// only to report the item; callers have no other use for it.
	RandomID string `json:"random_id"`

	randomID []byte
}

// Sponsored is the sponsored-message part of one content read: the items
// served for the broadcast channels whose posts the read returned.
type Sponsored struct {
	Messages []SponsoredMessage
	// Unavailable lists the channels ("channel:<id>") whose posts were
	// returned but whose sponsored messages could not be fetched. That is
	// an unknown, not "this channel has no ads": an empty Messages slice
	// says nothing about these channels.
	Unavailable []string
}

// sponsoredFetcher is the call fetchSponsored needs, so tests can answer it
// without a live MTProto client.
type sponsoredFetcher interface {
	MessagesGetSponsoredMessages(ctx context.Context, req *tg.MessagesGetSponsoredMessagesRequest) (tg.MessagesSponsoredMessagesClass, error)
}

// fetchSponsored asks Telegram for the sponsored messages of one broadcast
// channel whose posts a read is returning, and adds them to sp. shown is the
// number of the channel's posts in the read: Telegram asks for one item after
// the posts when the reply sets no posts_between, and one per posts_between
// posts otherwise, so only that many are kept.
//
// A failed call is not "no ads": the channel is recorded in sp.Unavailable
// and the posts are still returned (see Sponsored). Item text is never
// logged.
func fetchSponsored(ctx context.Context, api sponsoredFetcher, channelID int64, peer tg.InputPeerClass, shown int, sp *Sponsored) {
	channel := fmt.Sprintf("channel:%d", channelID)
	res, err := api.MessagesGetSponsoredMessages(ctx, &tg.MessagesGetSponsoredMessagesRequest{Peer: peer})
	if err != nil {
		slog.Warn("sponsored messages unavailable", "peer_redacted", RedactPeer(channel), "err", err)
		sp.Unavailable = append(sp.Unavailable, channel)
		return
	}
	switch r := res.(type) {
	case *tg.MessagesSponsoredMessagesEmpty:
		return
	case *tg.MessagesSponsoredMessages:
		keep := 1
		if r.PostsBetween > 0 {
			keep = shown / r.PostsBetween
			if keep < 1 {
				keep = 1
			}
		}
		if keep > len(r.Messages) {
			keep = len(r.Messages)
		}
		for _, m := range r.Messages[:keep] {
			label := SponsoredLabel
			if m.Recommended {
				label = RecommendedLabel
			}
			sp.Messages = append(sp.Messages, SponsoredMessage{
				Label:          label,
				Channel:        channel,
				Title:          m.Title,
				Text:           m.Message,
				URL:            m.URL,
				ButtonText:     m.ButtonText,
				SponsorInfo:    m.SponsorInfo,
				AdditionalInfo: m.AdditionalInfo,
				RandomID:       base64.StdEncoding.EncodeToString(m.RandomID),
				randomID:       m.RandomID,
			})
		}
	default:
		// A constructor added in a later layer: what it holds is unknown.
		slog.Warn("sponsored messages unavailable: unexpected reply", "peer_redacted", RedactPeer(channel), "type", fmt.Sprintf("%T", res))
		sp.Unavailable = append(sp.Unavailable, channel)
	}
}

// sponsoredViewer is the call reportSponsoredViewsWith needs.
type sponsoredViewer interface {
	MessagesViewSponsoredMessage(ctx context.Context, randomid []byte) (bool, error)
}

// ReportSponsoredViews tells Telegram that each item in msgs was shown, with
// one messages.viewSponsoredMessage call per item. Call it only with the
// items a result actually returned, after that result is built, so a read
// that failed afterwards reports nothing. It returns the number of reports
// that failed; a failure is logged and never fails the read.
func ReportSponsoredViews(ctx context.Context, c *gotdtelegram.Client, msgs []SponsoredMessage) int {
	if len(msgs) == 0 {
		return 0
	}
	return reportSponsoredViewsWith(ctx, c.API(), msgs)
}

func reportSponsoredViewsWith(ctx context.Context, api sponsoredViewer, msgs []SponsoredMessage) int {
	failed := 0
	for _, m := range msgs {
		if len(m.randomID) == 0 {
			continue
		}
		if _, err := api.MessagesViewSponsoredMessage(ctx, m.randomID); err != nil {
			failed++
			slog.Warn("sponsored message view not reported", "peer_redacted", RedactPeer(m.Channel), "err", err)
		}
	}
	return failed
}
