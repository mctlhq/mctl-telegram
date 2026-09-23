package broadcast

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Defaults for Config fields left at zero.
const (
	DefaultApprovalTTL    = 30 * time.Minute
	DefaultRecipientLimit = 1000
	DefaultBatchSize      = 20
	sampleSize            = 5
)

// ErrNotBroadcastAdmin is returned when an approval or cancellation comes
// from an identity outside the broadcast operator allow-list.
var ErrNotBroadcastAdmin = errors.New("not a broadcast operator")

// ErrNoEligibleRecipients is returned by Prepare when the audience resolves
// to nobody; there is nothing to approve.
var ErrNoEligibleRecipients = errors.New("the selector resolves to no eligible recipients")

// ErrRecipientLimit is returned by Prepare when the eligible audience exceeds
// the configured per-campaign limit.
var ErrRecipientLimit = errors.New("eligible audience exceeds the per-campaign recipient limit")

// Config is the operator-controlled configuration of the workflow.
type Config struct {
	// Operators is the allow-list of Telegram ids who may approve, cancel
	// or prepare broadcasts. Empty disables the workflow entirely.
	Operators map[int64]bool
	// ApprovalTTL is how long a prepared campaign stays approvable.
	ApprovalTTL time.Duration
	// RecipientLimit caps the eligible audience of one campaign.
	RecipientLimit int
	// BatchSize is the number of messages the delivery worker sends per
	// rate-limit window; used here only to estimate batches in the preview.
	BatchSize int
	// Policy resolves recipients' effective tiers.
	Policy Policy
}

func (c Config) withDefaults() Config {
	if c.ApprovalTTL <= 0 {
		c.ApprovalTTL = DefaultApprovalTTL
	}
	if c.RecipientLimit <= 0 {
		c.RecipientLimit = DefaultRecipientLimit
	}
	if c.BatchSize <= 0 {
		c.BatchSize = DefaultBatchSize
	}
	return c
}

// Store is the subset of *db.Store the service needs.
type Store interface {
	ListBroadcastRecipientFacts(ctx context.Context, now time.Time) ([]db.BroadcastRecipientFacts, error)
	CreateBroadcastCampaign(ctx context.Context, c db.BroadcastCampaign) error
	GetBroadcastCampaign(ctx context.Context, id string) (*db.BroadcastCampaign, error)
	ApproveBroadcastCampaign(ctx context.Context, id string, approver int64, contentHash, selectorHash string, now time.Time) error
	CancelBroadcastCampaign(ctx context.Context, id string, actor int64, now time.Time) error
}

// Service implements prepare, approve and cancel. It never sends anything:
// delivery is the worker's job and starts only from an approved campaign.
type Service struct {
	store Store
	cfg   Config
	now   func() time.Time
}

// NewService builds a Service. now may be nil (time.Now).
func NewService(store Store, cfg Config, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, cfg: cfg.withDefaults(), now: now}
}

// Enabled reports whether any operator is configured. With an empty
// allow-list the workflow is off: nobody can prepare or approve.
func (s *Service) Enabled() bool { return len(s.cfg.Operators) > 0 }

// IsOperator reports whether telegramID is on the operator allow-list.
func (s *Service) IsOperator(telegramID int64) bool { return s.cfg.Operators[telegramID] }

// Actor identifies who performs an operation.
type Actor struct {
	UserID     int64
	TelegramID int64
	// Surface names where the call came from (e.g. the MCP client name or
	// "web"), recorded on the campaign for audit.
	Surface string
}

// PrepareRequest is the whole caller-controlled input to a broadcast. Note
// the absence of any recipient field.
type PrepareRequest struct {
	Selector Selector
	Text     string
}

// SampleRecipient is one redacted entry of the preview sample: enough for an
// operator to sanity-check the audience, never enough to identify someone.
type SampleRecipient struct {
	TelegramID string `json:"telegram_id"`
	Tier       string `json:"tier"`
}

// Counts is the eligible/skipped breakdown of an audience.
type Counts struct {
	Eligible int            `json:"eligible"`
	Skipped  map[string]int `json:"skipped"`
}

// Preview is what Prepare returns and what a human approves.
type Preview struct {
	CampaignID       string            `json:"campaign_id"`
	Text             string            `json:"text"`
	ContentHash      string            `json:"content_hash"`
	Selector         Selector          `json:"selector"`
	SelectorHash     string            `json:"selector_hash"`
	Counts           Counts            `json:"counts"`
	Sample           []SampleRecipient `json:"sample"`
	EstimatedBatches int               `json:"estimated_batches"`
	ExpiresAt        time.Time         `json:"expires_at"`
}

// Resolve evaluates the whole population against a normalized selector.
func Resolve(sel Selector, facts []db.BroadcastRecipientFacts, p Policy, now time.Time) (eligible []db.BroadcastRecipientFacts, counts Counts) {
	counts.Skipped = make(map[string]int, len(SkipReasons()))
	for _, r := range SkipReasons() {
		counts.Skipped[string(r)] = 0
	}
	for _, f := range facts {
		d := Evaluate(sel, f, p, now)
		switch {
		case !d.InAudience:
		case d.Eligible:
			eligible = append(eligible, f)
		default:
			counts.Skipped[string(d.Reason)]++
		}
	}
	counts.Eligible = len(eligible)
	return eligible, counts
}

// Prepare validates and normalizes the request, resolves the audience
// server-side, and records a prepared campaign awaiting human approval. It
// sends nothing.
func (s *Service) Prepare(ctx context.Context, actor Actor, req PrepareRequest) (*Preview, error) {
	if !s.IsOperator(actor.TelegramID) {
		return nil, ErrNotBroadcastAdmin
	}
	sel, err := req.Selector.Normalize()
	if err != nil {
		return nil, err
	}
	text, err := NormalizeText(req.Text)
	if err != nil {
		return nil, err
	}
	selJSON, err := sel.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	facts, err := s.store.ListBroadcastRecipientFacts(ctx, now)
	if err != nil {
		return nil, err
	}
	eligible, counts := Resolve(sel, facts, s.cfg.Policy, now)
	if counts.Eligible == 0 {
		return nil, ErrNoEligibleRecipients
	}
	if counts.Eligible > s.cfg.RecipientLimit {
		return nil, fmt.Errorf("%w: %d eligible, limit %d", ErrRecipientLimit, counts.Eligible, s.cfg.RecipientLimit)
	}
	countsJSON, err := json.Marshal(counts)
	if err != nil {
		return nil, err
	}
	id, err := newCampaignID()
	if err != nil {
		return nil, err
	}
	p := &Preview{
		CampaignID:       id,
		Text:             text,
		ContentHash:      Hash(text),
		Selector:         sel,
		SelectorHash:     Hash(selJSON),
		Counts:           counts,
		EstimatedBatches: (counts.Eligible + s.cfg.BatchSize - 1) / s.cfg.BatchSize,
		ExpiresAt:        now.Add(s.cfg.ApprovalTTL),
	}
	for i := 0; i < len(eligible) && i < sampleSize; i++ {
		p.Sample = append(p.Sample, SampleRecipient{
			TelegramID: RedactID(eligible[i].TelegramID),
			Tier:       s.cfg.Policy.TierOf(eligible[i].TelegramID, eligible[i].AccessTier),
		})
	}
	if err := s.store.CreateBroadcastCampaign(ctx, db.BroadcastCampaign{
		ID:             id,
		Category:       sel.Category,
		SelectorJSON:   selJSON,
		SelectorHash:   p.SelectorHash,
		Content:        text,
		ContentHash:    p.ContentHash,
		CreatedBy:      actor.UserID,
		Surface:        actor.Surface,
		RecipientLimit: s.cfg.RecipientLimit,
		PreviewCounts:  string(countsJSON),
		ExpiresAt:      p.ExpiresAt,
	}); err != nil {
		return nil, err
	}
	return p, nil
}

// Approve releases a prepared campaign for delivery. contentHash and
// selectorHash must be the ones the approver was shown; the store refuses
// the transition unless both still match, the approval window is open and
// the campaign has not been approved before.
//
// The stored content and selector are also re-hashed here, so a row whose
// content was altered after preview (by anything other than Prepare) is
// refused as a mismatch rather than delivered.
func (s *Service) Approve(ctx context.Context, actor Actor, campaignID, contentHash, selectorHash string) error {
	if !s.IsOperator(actor.TelegramID) {
		return ErrNotBroadcastAdmin
	}
	c, err := s.store.GetBroadcastCampaign(ctx, campaignID)
	if err != nil {
		return err
	}
	if Hash(c.Content) != c.ContentHash || Hash(c.SelectorJSON) != c.SelectorHash {
		return db.ErrCampaignMismatch
	}
	return s.store.ApproveBroadcastCampaign(ctx, campaignID, actor.UserID, contentHash, selectorHash, s.now())
}

// Cancel stops a campaign that has not finished.
func (s *Service) Cancel(ctx context.Context, actor Actor, campaignID string) error {
	if !s.IsOperator(actor.TelegramID) {
		return ErrNotBroadcastAdmin
	}
	return s.store.CancelBroadcastCampaign(ctx, campaignID, actor.UserID, s.now())
}

// RedactID keeps the first two and last two digits of a Telegram id, enough
// to tell sample entries apart and never enough to identify the account.
func RedactID(id int64) string {
	s := strconv.FormatInt(id, 10)
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "…" + s[len(s)-2:]
}

func newCampaignID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("campaign id: %w", err)
	}
	return "bc_" + hex.EncodeToString(b[:]), nil
}
