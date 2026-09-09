package agentapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// newHarnessWithMetrics is newHarness plus a real, non-nil metrics.Registry
// wired into the Server — needed to assert on AgentPolicyDenialsTotal, which
// newHarness's plain construction leaves nil (metrics are optional).
func newHarnessWithMetrics(t *testing.T) (*testHarness, *metrics.Registry) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(testCryptKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := db.NewStore(conn, crypt)
	uid, err := store.EnsureUser(ctx, "owner", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	m := metrics.New()
	q := queue.New(store, "test-replica", m)
	srv := New(store, q, time.Minute, m).WithLongPollTimeout(150 * time.Millisecond)

	router := chi.NewRouter()
	srv.Register(router)

	h := &testHarness{
		t: t, srv: srv, store: store, router: router, userID: uid,
		id: &auth.Identity{UserID: uid, Subject: "tg:1", TelegramID: 1},
	}
	return h, m
}

// TestHandleProposeReply_DenyIncrementsPolicyDenialCounter asserts that a
// denied propose_reply increments AgentPolicyDenialsTotal labeled
// reason=<the actual DenyCode>, surface="propose_reply", by exactly 1, and
// that an Allow/RequireApproval decision increments nothing.
func TestHandleProposeReply_DenyIncrementsPolicyDenialCounter(t *testing.T) {
	h, m := newHarnessWithMetrics(t)
	h.seedProfile(db.AgentModeGuarded)
	conv := h.seedConversation(555)

	before := testutil.ToFloat64(m.AgentPolicyDenialsTotal.WithLabelValues(
		string(policy.DenyReplyURL), metrics.PolicySurfaceProposeReply))

	rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, Text: "Check out https://example.com for details",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	after := testutil.ToFloat64(m.AgentPolicyDenialsTotal.WithLabelValues(
		string(policy.DenyReplyURL), metrics.PolicySurfaceProposeReply))
	if after != before+1 {
		t.Fatalf("AgentPolicyDenialsTotal{reason=%s,surface=propose_reply} = %v, want %v",
			policy.DenyReplyURL, after, before+1)
	}
}

// TestHandleProposeReply_AllowDoesNotIncrementPolicyDenialCounter guards the
// Decision == Deny guard: an ordinary allowed reply must not touch the
// counter at all.
func TestHandleProposeReply_AllowDoesNotIncrementPolicyDenialCounter(t *testing.T) {
	h, m := newHarnessWithMetrics(t)
	h.seedProfile(db.AgentModeGuarded)
	if err := h.store.UpsertAgentProfile(context.Background(), db.AgentProfile{
		UserID: h.userID, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.",
		IntentAllowlist: "greet",
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	conv := h.seedConversation(555)

	rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, Intent: "greet", Text: "Hello there, thanks for reaching out.",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	mfs, err := m.Prometheus.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "mctl_agent_policy_denials_total" {
			for _, sample := range mf.GetMetric() {
				if sample.GetCounter().GetValue() > 0 {
					t.Fatalf("policy denial counter incremented for a non-deny decision: %+v", sample)
				}
			}
		}
	}
}
