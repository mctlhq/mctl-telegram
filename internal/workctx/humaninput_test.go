package workctx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const hiID = "hir-0123456789abcdef"

// hiRequestJSON is a request view in mctl-api's exact wire shape
// (humanInputView, mctl-api internal/api/handlers_human_input.go at the
// pinned revision), plus fields this adapter must never decode.
const hiRequestJSON = `{"request_id":"` + hiID + `","request_hash":"h1","request_version":2,"round":1,` +
	`"work_item_id":"wi_1","service":"mctl-telegram","proposal":"issue-571","workflow_id":"SECRET-WF","agent":"issue-investigator",` +
	`"question":"Which one?","reason":"Two readings.","response_type":"single_choice","options":["Alpha","Bravo"],` +
	`"context_refs":["https://github.com/mctlhq/mctl-telegram/issues/571"],"audience":"SECRET-AUD","eligible_actors":["github:SECRET-ACTOR"],` +
	`"can_respond":true,"created_at":"2026-10-03T10:00:00Z","expires_at":"2026-10-04T10:00:00Z","state":"pending",` +
	`"prompt":"SECRET-PROMPT","reasoning":"SECRET-REASONING","logs":"SECRET-LOGS"}`

// TestHumanInputRouteAllowlist checks the three human-input methods build
// exactly the relay routes and the exact wire shapes: list {"items","count"},
// the request view, and the response body {request_hash, value, surface}
// that mctl-api decodes with DisallowUnknownFields.
func TestHumanInputRouteAllowlist(t *testing.T) {
	type call struct{ method, path string }
	var calls []call
	var idem, actor, auth, reqID string
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, call{r.Method, r.URL.Path})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/human-input":
			_, _ = w.Write([]byte(`{"items":[` + hiRequestJSON + `],"count":1}`))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(hiRequestJSON))
		default:
			idem = r.Header.Get("Idempotency-Key")
			actor = r.Header.Get("X-MCTL-Surface-Actor")
			auth = r.Header.Get("Authorization")
			reqID = r.Header.Get("X-Request-Id")
			b := make([]byte, 4096)
			n, _ := r.Body.Read(b)
			raw = b[:n]
			_, _ = w.Write([]byte(`{"request_id":"` + hiID + `","status":"accepted","state":"resolved","respondent":"github:alice","received_at":"2026-10-03T10:01:00Z"}`))
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok", "tenant", nil)
	ctx := context.Background()

	list, err := c.ListHumanInput(ctx, 555)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v err=%v", list, err)
	}
	v := list[0]
	if v.RequestID != hiID || v.RequestVersion != 2 || v.ResponseType != HumanInputTypeSingleChoice || v.Reason != "Two readings." ||
		len(v.Options) != 2 || v.Options[1] != "Bravo" || v.ExpiresAt == "" || !v.Respondable() || len(v.ContextRefs) != 1 {
		t.Fatalf("list item = %+v", v)
	}
	if !strings.HasPrefix(v.CorrelationID, "tg-") {
		t.Fatalf("list items must carry the call's correlation id, got %q", v.CorrelationID)
	}
	got, err := c.GetHumanInput(ctx, 555, hiID)
	if err != nil || !strings.HasPrefix(got.CorrelationID, "tg-") || len(got.Options) != 2 {
		t.Fatalf("get = %+v err=%v", got, err)
	}
	resp, err := c.RespondHumanInput(ctx, 555, hiID, ResponseRequest{RequestHash: "h1", Value: "Bravo"}, "idem-1")
	if err != nil || resp.Status != HumanInputStatusAccepted {
		t.Fatalf("respond = %+v err=%v", resp, err)
	}
	want := []call{
		{"GET", "/api/v1/human-input"},
		{"GET", "/api/v1/human-input/" + hiID},
		{"POST", "/api/v1/human-input/" + hiID + "/response"},
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v", calls)
	}
	for i, w := range want {
		if calls[i] != w {
			t.Errorf("call %d = %v, want %v", i, calls[i], w)
		}
		for _, f := range []string{"approvals", "executions", "snapshot", "events", "/resume"} {
			if strings.Contains(calls[i].path, f) {
				t.Errorf("path %q contains forbidden segment %q", calls[i].path, f)
			}
		}
	}
	if idem != "idem-1" || actor != "555" || auth != "Bearer tok" || !strings.HasPrefix(reqID, "tg-") {
		t.Errorf("headers idem=%q actor=%q auth=%q x-request-id=%q", idem, actor, auth, reqID)
	}
	// Exactly mctl-api's three fields, decodable with DisallowUnknownFields.
	var body struct {
		RequestHash string          `json:"request_hash"`
		Value       json.RawMessage `json:"value"`
		Surface     string          `json:"surface"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("body %s is not mctl-api's shape: %v", raw, err)
	}
	if body.RequestHash != "h1" || string(body.Value) != `"Bravo"` || body.Surface != "telegram" {
		t.Errorf("body = %s", raw)
	}
}

// TestHumanInputPendingDeliveryIsNotAccepted: a 202 pending_delivery is a
// valid response but carries status pending_delivery, never accepted.
func TestHumanInputPendingDeliveryIsNotAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"request_id":"` + hiID + `","status":"pending_delivery","state":"pending","detail":"delivered; not yet confirmed by the workflow, resubmit the same response to check again"}`))
	}))
	defer srv.Close()
	resp, err := NewClient(srv.URL, "tok", "tenant", nil).RespondHumanInput(context.Background(), 555, hiID, ResponseRequest{RequestHash: "h", Value: "x"}, "")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if resp.Status != HumanInputStatusPendingDelivery {
		t.Fatalf("status = %q", resp.Status)
	}
}

// TestHumanInputErrorMapping covers mctl-api's response rejections, which are
// result objects ({"status":"rejected","state":...}), and the relay refusals
// ({"error": msg, "code": code}).
func TestHumanInputErrorMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"superseded", 409, `{"request_id":"` + hiID + `","status":"rejected","state":"superseded","detail":"request_hash does not match the current request"}`, ErrRequestSuperseded},
		{"invalid_value", 422, `{"request_id":"` + hiID + `","status":"rejected","state":"invalid_value","detail":"single_choice answer must be one of [SECRET-OPTION]"}`, ErrAnswerInvalid},
		{"refused_while_pending", 409, `{"request_id":"` + hiID + `","status":"rejected","state":"pending","detail":"the workflow refused this response"}`, ErrAnswerInvalid},
		{"expired", 409, `{"request_id":"` + hiID + `","status":"rejected","state":"expired"}`, ErrRequestNotActive},
		{"timed_out", 409, `{"request_id":"` + hiID + `","status":"rejected","state":"timed_out"}`, ErrRequestNotActive},
		{"not_pending", 409, `{"request_id":"` + hiID + `","status":"rejected","state":"not_pending","detail":"owning workflow not found"}`, ErrRequestNotActive},
		{"answered", 409, `{"request_id":"` + hiID + `","status":"rejected","state":"answered","detail":"the request was already answered"}`, ErrRequestNotActive},
		{"not_eligible", 403, `{"request_id":"` + hiID + `","status":"rejected","state":"not_eligible","detail":"github:SECRET-ACTOR is not an eligible respondent","respondent":"github:SECRET-ACTOR"}`, ErrNotEligible},
		{"link_not_found", 403, `{"error":"no verified link","code":"link_not_found"}`, ErrLinkNotFound},
		{"link_revoked", 403, `{"error":"link revoked","code":"link_revoked"}`, ErrLinkRevoked},
		{"actor_not_accepted", 400, `{"error":"the acting principal is taken from authentication","code":"actor_not_accepted"}`, ErrActorNotAccepted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := NewClient(srv.URL, "tok", "tenant", nil)
			_, err := c.RespondHumanInput(context.Background(), 555, hiID, ResponseRequest{RequestHash: "h", Value: "x"}, "k")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || !strings.HasPrefix(apiErr.CorrelationID, "tg-") {
				t.Errorf("APIError = %+v", apiErr)
			}
			// Rejection detail (it can list the options) and the
			// respondent's login never reach the error text.
			if strings.Contains(err.Error(), "SECRET") {
				t.Errorf("error text carries rejection detail: %v", err)
			}
		})
	}
}

// TestHumanInputUnrecognisedRejectionIsGeneric: a rejection state this
// adapter does not know maps onto no sentinel.
func TestHumanInputUnrecognisedRejectionIsGeneric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"request_id":"` + hiID + `","status":"rejected","state":"brand_new_state"}`))
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL, "tok", "tenant", nil).RespondHumanInput(context.Background(), 555, hiID, ResponseRequest{RequestHash: "h", Value: "x"}, "")
	for _, s := range []error{ErrRequestNotActive, ErrRequestSuperseded, ErrAnswerInvalid, ErrNotEligible} {
		if errors.Is(err, s) {
			t.Fatalf("unknown state mapped onto %v", s)
		}
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "brand_new_state" {
		t.Fatalf("err = %v", err)
	}
}

func TestHumanInputGetNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":"human-input request not found: ` + hiID + `"}`))
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL, "tok", "tenant", nil).GetHumanInput(context.Background(), 555, hiID); !errors.Is(err, ErrHumanInputNotFound) {
		t.Fatalf("err = %v, want ErrHumanInputNotFound", err)
	}
}

// TestHumanInputUnallowlistedFieldsNotDecoded asserts fields outside the
// allowlist in the wire JSON never reach the DTO.
func TestHumanInputUnallowlistedFieldsNotDecoded(t *testing.T) {
	var v RequestView
	if err := json.Unmarshal([]byte(hiRequestJSON), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	for _, secret := range []string{"SECRET-PROMPT", "SECRET-REASONING", "SECRET-LOGS", "SECRET-ACTOR", "SECRET-WF", "SECRET-AUD"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("DTO carries %s", secret)
		}
	}
}

// TestHumanInputMalformedResponsesAreErrors: a list without count, a short
// list, a malformed request id or a 2xx response without a known status is a
// failed read, never an empty or successful one.
func TestHumanInputMalformedResponsesAreErrors(t *testing.T) {
	cases := map[string]struct {
		path, body string
		call       func(*Client) error
	}{
		"list without count":  {"/api/v1/human-input", `{"items":[]}`, func(c *Client) error { _, err := c.ListHumanInput(context.Background(), 555); return err }},
		"list count mismatch": {"/api/v1/human-input", `{"items":[],"count":2}`, func(c *Client) error { _, err := c.ListHumanInput(context.Background(), 555); return err }},
		"empty list body":     {"/api/v1/human-input", ``, func(c *Client) error { _, err := c.ListHumanInput(context.Background(), 555); return err }},
		"bad request id": {"/api/v1/human-input", `{"items":[` + strings.Replace(hiRequestJSON, hiID, "hi_1", 1) + `],"count":1}`,
			func(c *Client) error { _, err := c.ListHumanInput(context.Background(), 555); return err }},
		"view without state": {"/api/v1/human-input/" + hiID, strings.Replace(hiRequestJSON, `"state":"pending",`, "", 1),
			func(c *Client) error { _, err := c.GetHumanInput(context.Background(), 555, hiID); return err }},
		"2xx rejected": {"/api/v1/human-input/" + hiID + "/response", `{"request_id":"` + hiID + `","status":"rejected"}`,
			func(c *Client) error {
				_, err := c.RespondHumanInput(context.Background(), 555, hiID, ResponseRequest{RequestHash: "h", Value: "x"}, "")
				return err
			}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("path = %s", r.URL.Path)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			if err := tc.call(NewClient(srv.URL, "tok", "tenant", nil)); !errors.Is(err, ErrIncompatibleSchema) {
				t.Fatalf("err = %v, want ErrIncompatibleSchema", err)
			}
		})
	}
}

func TestHumanInputRefusesMalformedRequestID(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", "tok", "tenant", nil)
	if _, err := c.GetHumanInput(context.Background(), 555, "../approvals"); err == nil {
		t.Fatal("malformed id must be refused before any call")
	}
	if _, err := c.RespondHumanInput(context.Background(), 555, "hir-x/../../approvals", ResponseRequest{}, ""); err == nil {
		t.Fatal("malformed id must be refused before any call")
	}
}

// An absent can_respond is a failed read, never an implicit false.
func TestHumanInputMissingCanRespondIsIncompatible(t *testing.T) {
	body := strings.Replace(hiRequestJSON, `"can_respond":true,`, "", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[` + body + `],"count":1}`))
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL, "tok", "tenant", nil).ListHumanInput(context.Background(), 555); !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("err = %v, want ErrIncompatibleSchema", err)
	}
}

// The rejection-object shape is read only on the response route: another
// route's body that happens to carry status/state keeps its code mapping.
func TestRejectionShapeScopedToResponseRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", strings.Repeat("x", 500))
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"error":"stale","code":"state_version_conflict","status":"rejected","state":"superseded"}`))
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL, "tok", "tenant", nil).GetWorkItem(context.Background(), 555, "wi_1")
	if !errors.Is(err, ErrStateVersionConflict) || errors.Is(err, ErrRequestSuperseded) {
		t.Fatalf("err = %v, want ErrStateVersionConflict only", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !strings.HasPrefix(apiErr.CorrelationID, "tg-") {
		t.Fatalf("an oversized upstream X-Request-ID must not replace the local id: %+v", apiErr)
	}
}
