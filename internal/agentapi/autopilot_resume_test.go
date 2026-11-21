package agentapi

import (
	"context"
	"net/http"
	"testing"
)

// TestAutopilotPause_ResumeRefusedForAgentCredentials pins #944: no agent
// credential may clear the pause, and the attempt is audited as a denied
// resume_autopilot rather than as a pause_autopilot success.
func TestAutopilotPause_ResumeRefusedForAgentCredentials(t *testing.T) {
	cases := []struct {
		name       string
		jobBound   bool
		body       any
		wantStatus int
		wantPaused bool // autopilot_paused after the call, starting from paused=true
		wantTool   string
		wantAudit  string
	}{
		{"account token, paused=false", false, map[string]any{"paused": false}, http.StatusForbidden, true, "resume_autopilot", "denied"},
		{"job token, paused=false", true, map[string]any{"paused": false}, http.StatusForbidden, true, "resume_autopilot", "denied"},
		{"account token, paused=true", false, map[string]any{"paused": true}, http.StatusOK, true, "pause_autopilot", "ok"},
		{"account token, empty object defaults to pause", false, map[string]any{}, http.StatusOK, true, "pause_autopilot", "ok"},
		{"job token, empty object defaults to pause", true, map[string]any{}, http.StatusOK, true, "pause_autopilot", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newBindingFixture(t)
			ctx := context.Background()
			if err := f.h.store.SetAgentAutopilotPaused(ctx, f.h.userID, true); err != nil {
				t.Fatal(err)
			}
			id := f.h.id
			if tc.jobBound {
				id = f.jobIdentity
			}
			rec := f.h.doAs(id, "POST", "/autopilot/pause", tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			p, err := f.h.store.GetAgentProfile(ctx, f.h.userID)
			if err != nil {
				t.Fatal(err)
			}
			if p.AutopilotPaused != tc.wantPaused {
				t.Errorf("autopilot_paused = %v, want %v", p.AutopilotPaused, tc.wantPaused)
			}
			var n int
			if err := f.h.store.DB.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM audit_logs WHERE tool_name = $1 AND status = $2`,
				tc.wantTool, tc.wantAudit).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Errorf("audit rows (%s, %s) = %d, want 1", tc.wantTool, tc.wantAudit, n)
			}
		})
	}
}
