package agentapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// The three managed-runtime refusals are caller errors, not server faults:
// the admin route must answer them with a 4xx and the message, never 500.
func TestWriteInstallError_ManagedKindsAreClientErrors(t *testing.T) {
	for _, tc := range []struct {
		kind assistantinstall.Kind
		want int
	}{
		{assistantinstall.KindManagedConsentRequired, http.StatusBadRequest},
		{assistantinstall.KindManagedDisabled, http.StatusConflict},
		{assistantinstall.KindManagedQuota, http.StatusConflict},
	} {
		rec := httptest.NewRecorder()
		writeInstallError(rec, &assistantinstall.Error{Kind: tc.kind, Msg: "refused"}, false)
		if rec.Code != tc.want {
			t.Errorf("kind %d: status = %d, want %d (body %s)", tc.kind, rec.Code, tc.want, rec.Body.String())
		}
	}
}

// The admin install route cannot move an account to managed, with or without
// a consent in the document, and answers 409 without touching the profile.
func TestAdminAgentInstallHandler_ManagedDocumentIsRefused(t *testing.T) {
	ctx := context.Background()
	store := newProfileTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 779, "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	h := NewAdminAgentInstallHandler(store, catalog, nil)
	for _, extra := range []string{`"runtime":"managed",`, `"runtime":"managed","consent":"managed-data-flow/v1",`} {
		body := `{"telegram_id":779,"install":{"apiVersion":"assistants.mctl.ai/v1alpha1","kind":"AssistantInstall","spec":{` + extra +
			`"assistant":{"name":"hr-recruiter","version":"0.1.0"},"mode":"observe","values":{"name":"Alice","role":"Engineer"}}}}`
		req := httptest.NewRequest(http.MethodPut, "/api/admin/agent/install", bytes.NewBufferString(body))
		req = req.WithContext(auth.With(req.Context(), adminIdentity()))
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s: status = %d %s, want 409", extra, rec.Code, rec.Body)
		}
	}
	if p, err := store.GetAgentProfile(ctx, uid); err == nil && p.Runtime != "" && p.Runtime != db.RuntimeOwn {
		t.Fatalf("runtime = %q after a refused install", p.Runtime)
	}
}
