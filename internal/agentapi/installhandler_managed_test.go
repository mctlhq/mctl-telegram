package agentapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
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
