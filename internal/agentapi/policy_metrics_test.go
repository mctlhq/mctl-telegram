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

// TestHandleOwnerFacing_DenyIncrementsPolicyDenialCounter closes issue #586.
// policySurfaceForOwnerTool is unit-tested in ownersurface_test.go, and the
// three other denial surfaces are pinned end to end, but nothing asserted that
// handleOwnerFacing increments the counter at all — deleting that `if` block
// left every test in the repo green.
//
// Both owner-facing tools are covered because #583 split them into distinct
// surfaces; a single case would not catch the two being swapped. reason is
// asserted alongside surface so the code plumbing is pinned too.
//
// A denial here is reachable through AGENT_KILL_SWITCH or mode=off only:
// owner-facing action types short-circuit to Allow *after* those two gates,
// and are exempt from the autopilot pause (#581). A denial is a 200 carrying
// decision="deny", not an error status.
func TestHandleOwnerFacing_DenyIncrementsPolicyDenialCounter(t *testing.T) {
	for _, tc := range []struct {
		path    string
		surface string
	}{
		{"/notify/summary", metrics.PolicySurfaceOwnerSummary},
		{"/actions/request_owner_approval", metrics.PolicySurfaceOwnerApproval},
	} {
		t.Run(tc.surface, func(t *testing.T) {
			// One harness per subtest: the store is a shared in-memory DB.
			h, m := newHarnessWithMetrics(t)
			h.seedProfile(db.AgentModeObserve)
			h.srv.GlobalKill = true

			before := testutil.ToFloat64(m.AgentPolicyDenialsTotal.WithLabelValues(
				string(policy.DenyGlobalKill), tc.surface))

			rec := h.do("POST", tc.path, ownerNotifyRequest{Text: "Daily digest"})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (a denial is a normal response), body=%s", rec.Code, rec.Body.String())
			}
			var body struct {
				Decision string `json:"decision"`
			}
			decodeBody(t, rec, &body)
			if body.Decision != "deny" {
				t.Fatalf("decision = %q, want deny — the test did not reach the counted branch", body.Decision)
			}

			after := testutil.ToFloat64(m.AgentPolicyDenialsTotal.WithLabelValues(
				string(policy.DenyGlobalKill), tc.surface))
			if after != before+1 {
				t.Fatalf("AgentPolicyDenialsTotal{reason=%s,surface=%s} = %v, want %v",
					policy.DenyGlobalKill, tc.surface, after, before+1)
			}

			// The other owner surface, and the unmapped fallback, must stay
			// flat — otherwise a swapped or defaulted surface argument would
			// still pass the assertion above.
			for _, other := range []string{
				metrics.PolicySurfaceOwnerSummary,
				metrics.PolicySurfaceOwnerApproval,
				metrics.PolicySurfaceUnknown,
			} {
				if other == tc.surface {
					continue
				}
				if got := testutil.ToFloat64(m.AgentPolicyDenialsTotal.WithLabelValues(
					string(policy.DenyGlobalKill), other)); got != 0 {
					t.Fatalf("AgentPolicyDenialsTotal{reason=%s,surface=%s} = %v, want 0",
						policy.DenyGlobalKill, other, got)
				}
			}
		})
	}
}
