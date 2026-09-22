package notify

import "testing"

// TestClassifyDelivery covers every mapping row from design.md plus several
// unrecognised descriptions, all of which must come back non-conclusive so a
// transient or unfamiliar failure never licenses a state write.
func TestClassifyDelivery(t *testing.T) {
	tests := []struct {
		name        string
		httpStatus  int
		description string
		wantState   string
		wantReason  string
		wantConclus bool
	}{
		{"200 OK is reachable", 200, "", StateReachable, "delivered", true},
		{"403 bot blocked", 403, "Forbidden: bot was blocked by the user", StateBlocked, "bot_blocked", true},
		{"403 user deactivated", 403, "Forbidden: user is deactivated", StateBlocked, "user_deactivated", true},
		{"403 cannot initiate conversation", 403, "Forbidden: bot can't initiate conversation with a user", StateCannotInitiate, "cannot_initiate_conversation", true},
		{"400 chat not found", 400, "Bad Request: chat not found", StateCannotInitiate, "chat_not_found", true},

		// Non-conclusive: transient / retryable.
		{"429 too many requests", 429, "Too Many Requests: retry later", "", "", false},
		{"500 internal server error", 500, "Internal Server Error", "", "", false},
		{"502 bad gateway", 502, "Bad Gateway", "", "", false},
		{"503 service unavailable", 503, "Service Unavailable", "", "", false},

		// Non-conclusive: recognised status, unrecognised description.
		{"403 unrecognised description", 403, "Forbidden: some new reason telegram invented", "", "", false},
		{"400 unrecognised description", 400, "Bad Request: something else entirely", "", "", false},

		// Non-conclusive: entirely unrecognised status.
		{"418 teapot", 418, "I'm a teapot", "", "", false},
		{"404 not found (not a documented mapping)", 404, "Not Found", "", "", false},
		{"401 unauthorized", 401, "Unauthorized", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyDelivery(tc.httpStatus, tc.description)
			if got.Conclusive != tc.wantConclus {
				t.Fatalf("Conclusive = %v, want %v (outcome=%+v)", got.Conclusive, tc.wantConclus, got)
			}
			if !tc.wantConclus {
				// Non-conclusive outcomes must not carry a state that a
				// careless caller could mistake for something to persist.
				return
			}
			if got.State != tc.wantState {
				t.Errorf("State = %q, want %q", got.State, tc.wantState)
			}
			if got.ReasonCode != tc.wantReason {
				t.Errorf("ReasonCode = %q, want %q", got.ReasonCode, tc.wantReason)
			}
		})
	}
}

func TestAPIError_Error(t *testing.T) {
	err := &APIError{StatusCode: 403, Description: "Forbidden: bot was blocked by the user"}
	got := err.Error()
	want := "telegram bot api: HTTP 403: Forbidden: bot was blocked by the user"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
