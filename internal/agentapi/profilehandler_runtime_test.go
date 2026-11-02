package agentapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestAdminAgentProfileHandler_Runtime(t *testing.T) {
	ctx := context.Background()
	store := newProfileTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 777, "carol", "Carol")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureAgentProfile(ctx, uid); err != nil {
		t.Fatal(err)
	}
	on := NewAdminAgentProfileHandlerWithManaged(store, assistantinstall.ManagedRuntime{Enabled: true, MaxAccounts: 5})
	off := NewAdminAgentProfileHandlerWithManaged(store, assistantinstall.ManagedRuntime{})

	// Omitted runtime leaves it alone; a consent key is rejected.
	if rec := doProfileReq(on, adminIdentity(), `{"telegram_id":777,"mode":"observe"}`); rec.Code != http.StatusOK {
		t.Fatalf("omitted: %d %s", rec.Code, rec.Body)
	}
	if rec := doProfileReq(on, adminIdentity(), `{"telegram_id":777,"runtime":"managed","consent":"managed-data-flow/v1"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("consent key: %d", rec.Code)
	}
	if rec := doProfileReq(on, adminIdentity(), `{"telegram_id":777,"runtime":"remote"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad runtime: %d", rec.Code)
	}
	// The owner never consented.
	if rec := doProfileReq(on, adminIdentity(), `{"telegram_id":777,"runtime":"managed"}`); rec.Code != http.StatusConflict {
		t.Fatalf("no consent: %d %s", rec.Code, rec.Body)
	}
	// The owner consented.
	// The owner consented two days ago; an admin switch today must not move it.
	v, now := db.ManagedConsentCurrent, time.Now().Add(-48*time.Hour)
	if err := store.UpdateAgentProfileFields(ctx, uid, db.AgentProfileUpdate{ManagedConsentVersion: &v, ManagedConsentAt: &now}); err != nil {
		t.Fatal(err)
	}
	if rec := doProfileReq(off, adminIdentity(), `{"telegram_id":777,"runtime":"managed"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("flag off: %d %s", rec.Code, rec.Body)
	}
	if rec := doProfileReq(on, adminIdentity(), `{"telegram_id":777,"runtime":"managed"}`); rec.Code != http.StatusOK {
		t.Fatalf("managed: %d %s", rec.Code, rec.Body)
	}
	p, _ := store.GetAgentProfile(ctx, uid)
	if p.Runtime != "managed" {
		t.Fatalf("runtime = %q", p.Runtime)
	}
	// The admin switch must keep the owner's original consent time: it is the
	// moment of the owner's consent, not of the administrative change.
	if p.ManagedConsentAt.Sub(now).Abs() > time.Second {
		t.Fatalf("consent time rewritten: stored %v, owner consented %v", p.ManagedConsentAt, now)
	}
	// Back to own always works, flag off included.
	if rec := doProfileReq(off, adminIdentity(), `{"telegram_id":777,"runtime":"own"}`); rec.Code != http.StatusOK {
		t.Fatalf("own: %d %s", rec.Code, rec.Body)
	}
	// Switching back to own erased the stored consent, so the quota check
	// below needs the owner's consent again to be reached.
	if p, _ = store.GetAgentProfile(ctx, uid); p.ManagedConsentVersion != "" || !p.ManagedConsentAt.IsZero() {
		t.Fatalf("consent survived managed -> own: %q %v", p.ManagedConsentVersion, p.ManagedConsentAt)
	}
	fresh := time.Now()
	if err := store.UpdateAgentProfileFields(ctx, uid, db.AgentProfileUpdate{ManagedConsentVersion: &v, ManagedConsentAt: &fresh}); err != nil {
		t.Fatal(err)
	}
	// Quota exhausted.
	full := NewAdminAgentProfileHandlerWithManaged(store, assistantinstall.ManagedRuntime{Enabled: true, MaxAccounts: 0})
	if rec := doProfileReq(full, adminIdentity(), `{"telegram_id":777,"runtime":"managed"}`); rec.Code != http.StatusConflict {
		t.Fatalf("quota: %d %s", rec.Code, rec.Body)
	}
}

// The owner opts out (managed -> own through the install service). An admin
// must not be able to put the account back on managed with the consent the
// owner gave before opting out.
func TestAdminAgentProfileHandler_OptOutThenAdminCannotReuseOldConsent(t *testing.T) {
	ctx := context.Background()
	store := newProfileTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 778, "dana", "Dana")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureAgentProfile(ctx, uid); err != nil {
		t.Fatal(err)
	}
	managed := assistantinstall.ManagedRuntime{Enabled: true, MaxAccounts: 5}
	h := NewAdminAgentProfileHandlerWithManaged(store, managed)
	v, at, rt := db.ManagedConsentCurrent, time.Now().Add(-time.Hour), db.RuntimeManaged
	if err := store.UpdateAgentProfileFields(ctx, uid, db.AgentProfileUpdate{Runtime: &rt, ManagedConsentVersion: &v, ManagedConsentAt: &at}); err != nil {
		t.Fatal(err)
	}
	// The opt-out, as the owner does it: managed -> own.
	ch, rerr := managed.DecideRuntime(db.RuntimeManaged, db.RuntimeOwn, "", time.Now())
	if rerr != nil {
		t.Fatal(rerr)
	}
	var up db.AgentProfileUpdate
	ch.Apply(&up)
	if err := store.UpdateAgentProfileFields(ctx, uid, up); err != nil {
		t.Fatal(err)
	}
	rec := doProfileReq(h, adminIdentity(), `{"telegram_id":778,"runtime":"managed"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("admin re-enable with the old consent: %d %s, want 409 managed_consent_required", rec.Code, rec.Body)
	}
	if p, _ := store.GetAgentProfile(ctx, uid); p.Runtime != db.RuntimeOwn {
		t.Fatalf("runtime = %q, want own", p.Runtime)
	}
}
