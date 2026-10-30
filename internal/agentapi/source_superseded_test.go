package agentapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// TestHandleProposeReply_SourceSupersededIsDenied: a worker proposing a
// reply for a job whose message the sender has since edited or deleted gets
// the draft stored as denied with the reason, and no approval code (#949,
// #950).
func TestHandleProposeReply_SourceSupersededIsDenied(t *testing.T) {
	for _, tc := range []struct {
		name       string
		supersede  func(t *testing.T, h *testHarness, convID int64)
		wantReason string
	}{
		{"edited", func(t *testing.T, h *testHarness, convID int64) {
			if _, ok, err := h.store.InsertEventEnqueueJobAndTouch(context.Background(), db.IncomingEvent{
				EventID: "evt:v1:1:555:10:e100:aa", UserID: h.userID, Kind: db.EventKindMessageEdit,
				ChatTGID: 555, SenderTGID: 555, MessageID: 10, Body: "Actually, Friday",
			}, convID); err != nil || !ok {
				t.Fatalf("ingest edit: ok=%v err=%v", ok, err)
			}
		}, db.ReasonSourceEdited},
		{"deleted", func(t *testing.T, h *testHarness, _ int64) {
			if _, err := h.store.RecordMessageDelete(context.Background(), h.userID, 1, 10); err != nil {
				t.Fatalf("record delete: %v", err)
			}
		}, db.ReasonSourceDeleted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, m := newHarnessWithMetrics(t)
			h.seedProfile(db.AgentModeObserve)
			conv := h.seedConversation(555)
			ctx := context.Background()
			if _, ok, err := h.store.InsertEventEnqueueJobAndTouch(ctx, db.IncomingEvent{
				EventID: "evt:v1:1:555:10", UserID: h.userID, Kind: db.EventKindPrivateMessage,
				ChatTGID: 555, SenderTGID: 555, MessageID: 10, Body: "Can you do Thursday?",
			}, conv.ID); err != nil || !ok {
				t.Fatalf("ingest: ok=%v err=%v", ok, err)
			}
			jobs, err := h.store.ClaimAgentJobs(ctx, "r", h.userID, 1)
			if err != nil || len(jobs) != 1 {
				t.Fatalf("claim: %d jobs, err=%v", len(jobs), err)
			}
			tc.supersede(t, h, conv.ID)

			before := testutil.ToFloat64(m.AgentPolicyDenialsTotal.WithLabelValues(
				string(policy.DenySourceSuperseded), metrics.PolicySurfaceProposeReply))
			rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
				ConversationID: conv.ID, JobID: jobs[0].ID, Attempt: jobs[0].Attempts,
				Intent: "schedule", Text: "Thursday works for me.",
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
			}
			var resp actionResponse
			decodeBody(t, rec, &resp)
			if resp.Status != db.ActionDenied || resp.ApprovalCode != "" {
				t.Fatalf("response = %+v, want denied without a code", resp)
			}
			a, err := h.store.GetAgentAction(ctx, h.userID, resp.ActionID)
			if err != nil {
				t.Fatalf("get action: %v", err)
			}
			if a.Status != db.ActionDenied || a.PolicyReasons != tc.wantReason {
				t.Fatalf("action = %s %q, want denied %q", a.Status, a.PolicyReasons, tc.wantReason)
			}
			after := testutil.ToFloat64(m.AgentPolicyDenialsTotal.WithLabelValues(
				string(policy.DenySourceSuperseded), metrics.PolicySurfaceProposeReply))
			if after != before+1 {
				t.Fatalf("denials = %v, want %v", after, before+1)
			}
			var notes int
			if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1`, h.userID).Scan(&notes); err != nil {
				t.Fatal(err)
			}
			if notes != 0 {
				t.Fatalf("owner notifications = %d, want none for a withdrawn draft", notes)
			}
		})
	}
}
