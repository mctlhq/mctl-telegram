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
	// Quota exhausted.
	full := NewAdminAgentProfileHandlerWithManaged(store, assistantinstall.ManagedRuntime{Enabled: true, MaxAccounts: 0})
	if rec := doProfileReq(full, adminIdentity(), `{"telegram_id":777,"runtime":"managed"}`); rec.Code != http.StatusConflict {
		t.Fatalf("quota: %d %s", rec.Code, rec.Body)
	}
}
