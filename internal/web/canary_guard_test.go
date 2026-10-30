package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/canaryguard"
)

// Issue #961: every web path that ends the monitoring canary's session asks
// for a second, deliberate step, and records the override when it is given.

const (
	manageDisconnectTool = "POST /telegram/connect/manage/disconnect"
	canaryConfirmForm    = `name="confirm_canary" value="1"`
)

// The first Disconnect press on the canary account only renders the
// confirmation; nothing is revoked or audited as a disconnect.
func TestManageDisconnect_CanaryAsksForConfirmation(t *testing.T) {
	f := newAccountManageFixture(t, accountManageCanaryTGID)
	rec := f.call(http.MethodPost, "manage", "", f.narrowedBrowserToken())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with the confirmation page; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "monitoring canary") || !strings.Contains(body, canaryConfirmForm) {
		t.Fatalf("confirmation page must name the canary and carry the confirm form; body=%s", body)
	}
	if n := f.activeSessions(); n != 1 {
		t.Fatalf("active sessions = %d after the first press, want 1", n)
	}
	if tool, _, _ := f.latestAuditOrNone(); strings.HasPrefix(tool, manageDisconnectTool) {
		t.Fatalf("the first press must not be audited as a disconnect, got %q", tool)
	}
}

func TestManageDisconnect_CanaryConfirmedIsAuditedAsOverride(t *testing.T) {
	f := newAccountManageFixture(t, accountManageCanaryTGID)
	rec := f.call(http.MethodPost, "manage-confirm-canary", "", f.narrowedBrowserToken())
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if n := f.activeSessions(); n != 0 {
		t.Fatalf("active sessions = %d after the confirmed disconnect, want 0", n)
	}
	if tool, status, _ := f.latestAudit(); tool != manageDisconnectTool+canaryguard.OverrideSuffix || status != "ok" {
		t.Fatalf("audit = (%q, %q), want the override recorded as ok", tool, status)
	}
}

// The manage page tells the owner up front that this is the canary account.
func TestManagePage_MarksTheCanaryAccount(t *testing.T) {
	for _, tc := range []struct {
		name string
		tgID int64
		want bool
	}{
		{"canary", accountManageCanaryTGID, true},
		{"ordinary account", 7700191, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAccountManageFixture(t, tc.tgID)
			rec := f.call(http.MethodGet, "manage-page", "", f.narrowedBrowserToken())
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := strings.Contains(rec.Body.String(), `id="canary-account"`); got != tc.want {
				t.Fatalf("canary note shown = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAccountEndpoints_CanaryNeedsConfirmation(t *testing.T) {
	for _, tc := range []struct {
		method, path, tool string
		intact             func(f *accountManageFixture) bool
	}{
		{http.MethodPost, "/disconnect", "POST /api/account/disconnect", func(f *accountManageFixture) bool { return f.activeSessions() == 1 }},
		{http.MethodDelete, "/", "DELETE /api/account", func(f *accountManageFixture) bool { return f.accountRows() == 1 }},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			f := newAccountManageFixture(t, accountManageCanaryTGID)
			token := f.accessToken("dcr-client", "telegram:messages:read", "account:manage")

			rec := f.call(tc.method, tc.path, token, "")
			if rec.Code != http.StatusConflict {
				t.Fatalf("unconfirmed status = %d, want 409; body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "confirm_canary=true") {
				t.Fatalf("refusal must name the confirmation; body=%s", rec.Body.String())
			}
			if !tc.intact(f) {
				t.Fatal("a refused call must leave the canary account intact")
			}
			if tool, status, reason := f.latestAudit(); tool != tc.tool || status != "error" || reason != reasonRefused {
				t.Fatalf("refusal audit = (%q, %q, %q), want (%q, error, %q)", tool, status, reason, tc.tool, reasonRefused)
			}

			rec = f.call(tc.method, tc.path+"?confirm_canary=true", token, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("confirmed status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			if tc.intact(f) {
				t.Fatal("a confirmed call must end the canary account's session")
			}
			if tool, status, _ := f.latestAuditOrNone(); tool != tc.tool+canaryguard.OverrideSuffix || status != "ok" {
				t.Fatalf("override audit = (%q, %q), want (%q, ok)", tool, status, tc.tool+canaryguard.OverrideSuffix)
			}
		})
	}
}
