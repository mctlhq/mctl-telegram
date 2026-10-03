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

const hiRequestJSON = `{"schema_version":"workitem/v1","request_id":"hi_1","request_hash":"h1","version":2,"kind":"single_choice","state":"pending","question":"Which one?","options":[{"id":"a","label":"A"},{"id":"b","label":"B"}],"prompt":"SECRET-PROMPT","reasoning":"SECRET-REASONING","logs":"SECRET-LOGS"}`

// TestHumanInputRouteAllowlist checks the three human-input methods build
// exactly the reserved relay routes, never an approval or execution route.
func TestHumanInputRouteAllowlist(t *testing.T) {
	type call struct{ method, path string }
	var calls []call
	var idem, actor, auth string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, call{r.Method, r.URL.Path})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "corr-1")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/human-input":
			_, _ = w.Write([]byte(`{"schema_version":"workitem/v1","requests":[` + hiRequestJSON + `]}`))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(hiRequestJSON))
		default:
			idem = r.Header.Get("Idempotency-Key")
			actor = r.Header.Get("X-MCTL-Surface-Actor")
			auth = r.Header.Get("Authorization")
			_ = json.NewDecoder(r.Body).Decode(&body)
			_, _ = w.Write([]byte(`{"schema_version":"workitem/v1","request_id":"hi_1","state":"answered"}`))
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok", "tenant", nil)
	ctx := context.Background()

	list, err := c.ListHumanInput(ctx, 555)
	if err != nil || len(list) != 1 || list[0].RequestID != "hi_1" || list[0].CorrelationID != "" {
		// list-level correlation id lives on the envelope, not the items.
		t.Fatalf("list = %+v err=%v", list, err)
	}
	got, err := c.GetHumanInput(ctx, 555, "hi_1")
	if err != nil || got.CorrelationID != "corr-1" || len(got.Options) != 2 {
		t.Fatalf("get = %+v err=%v", got, err)
	}
	resp, err := c.RespondHumanInput(ctx, 555, "hi_1", ResponseRequest{RequestHash: "h1", Kind: HumanInputKindSingleChoice, Value: "b"}, "idem-1")
	if err != nil || resp.State != HumanInputStateAnswered {
		t.Fatalf("respond = %+v err=%v", resp, err)
	}
	want := []call{
		{"GET", "/api/v1/human-input"},
		{"GET", "/api/v1/human-input/hi_1"},
		{"POST", "/api/v1/human-input/hi_1/response"},
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
	if idem != "idem-1" || actor != "555" || auth != "Bearer tok" {
		t.Errorf("headers idem=%q actor=%q auth=%q", idem, actor, auth)
	}
	if len(body) != 3 || body["request_hash"] != "h1" || body["kind"] != "single_choice" || body["value"] != "b" {
		t.Errorf("body = %v", body)
	}
}

func TestHumanInputErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		code   string
		want   error
	}{
		{409, "request_hash_mismatch", ErrRequestSuperseded},
		{409, "request_superseded", ErrRequestSuperseded},
		{410, "request_expired", ErrRequestNotActive},
		{409, "request_cancelled", ErrRequestNotActive},
		{409, "request_not_active", ErrRequestNotActive},
		{409, "already_answered", ErrAlreadyAnswered},
		{403, "not_eligible", ErrNotEligible},
		{403, "link_not_found", ErrLinkNotFound},
		{422, "answer_invalid", ErrAnswerInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Request-ID", "corr-9")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":"` + tc.code + `","message":"detail"}`))
			}))
			defer srv.Close()
			c := NewClient(srv.URL, "tok", "tenant", nil)
			_, err := c.RespondHumanInput(context.Background(), 555, "hi_1", ResponseRequest{RequestHash: "h", Kind: "free_text", Value: "x"}, "k")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.CorrelationID != "corr-9" || apiErr.StatusCode != tc.status {
				t.Errorf("APIError = %+v", apiErr)
			}
		})
	}
}

// TestHumanInputUnallowlistedFieldsNotDecoded asserts prompt/reasoning/logs in
// the wire JSON never reach the DTO.
func TestHumanInputUnallowlistedFieldsNotDecoded(t *testing.T) {
	var v RequestView
	if err := json.Unmarshal([]byte(hiRequestJSON), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	for _, secret := range []string{"SECRET-PROMPT", "SECRET-REASONING", "SECRET-LOGS"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("DTO carries %s", secret)
		}
	}
}

func TestHumanInputSchemaVersionRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Replace(hiRequestJSON, "workitem/v1", "workitem/v9", 1)))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok", "tenant", nil)
	if _, err := c.GetHumanInput(context.Background(), 555, "hi_1"); !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("err = %v, want ErrIncompatibleSchema", err)
	}
}
