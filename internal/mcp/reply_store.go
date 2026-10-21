package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// replyDraft is what draft_reply stored and send_reply delivers. The
// recipient and text live here, on the server; send_reply takes only the id,
// so nothing the model passes at send time can change either.
type replyDraft struct {
	ID        string
	UserID    int64
	Profile   string
	Target    *telegram.ReplyTarget
	Text      string
	ExpiresAt time.Time
}

// errReplyDraftNotFound collapses unknown, expired, already-used and
// issued-to-someone-else into one answer, so an id cannot be probed for
// whose it was. Like every confirmation in this package the drafts are
// in-memory and lost on restart; the message tells the model what to do.
var errReplyDraftNotFound = errors.New("confirmation_id not found, expired, or already used — call draft_reply again")

// ReplyStore holds draft_reply confirmations: in-memory, single-shot, valid
// for ConfirmationTTL, bound to the identity and the profile that drafted.
type ReplyStore struct {
	mu  sync.Mutex
	m   map[string]*replyDraft
	now func() time.Time
}

func NewReplyStore() *ReplyStore {
	return &ReplyStore{m: map[string]*replyDraft{}, now: time.Now}
}

// Issue stores a draft and returns it with its id and expiry filled in.
func (s *ReplyStore) Issue(userID int64, profile string, target *telegram.ReplyTarget, text string) (*replyDraft, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// Nothing else sweeps the map; dropping expired drafts here bounds it by
	// what one TTL window of drafting can produce.
	for id, d := range s.m {
		if now.After(d.ExpiresAt) {
			delete(s.m, id)
		}
	}
	d := &replyDraft{
		ID:        "cr_" + hex.EncodeToString(raw),
		UserID:    userID,
		Profile:   profile,
		Target:    target,
		Text:      text,
		ExpiresAt: now.Add(ConfirmationTTL),
	}
	s.m[d.ID] = d
	return d, nil
}

// Consume removes the draft and returns it if it is live and belongs to the
// same identity under the same profile. Any failure also removes it: a
// draft is used once, or not at all.
func (s *ReplyStore) Consume(id string, userID int64, profile string) (*replyDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.m[id]
	if !ok {
		return nil, errReplyDraftNotFound
	}
	delete(s.m, id)
	if s.now().After(d.ExpiresAt) || d.UserID != userID || d.Profile != profile {
		return nil, errReplyDraftNotFound
	}
	return d, nil
}
