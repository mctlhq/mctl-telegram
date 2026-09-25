package workctx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// forbiddenActorFields must never appear (by field name or json tag) on any
// exported request struct in this package — see requirements.md's "SHALL
// omit every actor-naming field" acceptance criterion.
var forbiddenActorFields = []string{"actor", "actor_subject", "created_by", "principal", "on_behalf_of"}

// forbiddenExecutionIdentityFields must never appear either: a surface
// requests execution, it never declares execution identity.
var forbiddenExecutionIdentityFields = []string{"engine", "engine_ref", "execution_id"}

// requestStructs lists every exported request struct this package exposes
// to a caller building a body — the reflection tests below walk exactly
// this set. If a new request struct is added, add it here too.
func requestStructs() map[string]reflect.Type {
	return map[string]reflect.Type{
		"CreateRequest":     reflect.TypeOf(CreateRequest{}),
		"IntentRequest":     reflect.TypeOf(IntentRequest{}),
		"ExecutionRequest":  reflect.TypeOf(ExecutionRequest{}),
		"SurfaceRefRequest": reflect.TypeOf(SurfaceRefRequest{}),
	}
}

func fieldNamesAndTags(t reflect.Type) []string {
	var names []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		names = append(names, strings.ToLower(f.Name))
		if tag, ok := f.Tag.Lookup("json"); ok {
			tagName := strings.Split(tag, ",")[0]
			if tagName != "" {
				names = append(names, strings.ToLower(tagName))
			}
		}
	}
	return names
}

// TestNoActorField is T2: no exported request struct may carry an
// actor-naming field, by field name or json tag.
func TestNoActorField(t *testing.T) {
	for name, typ := range requestStructs() {
		names := fieldNamesAndTags(typ)
		for _, forbidden := range forbiddenActorFields {
			for _, n := range names {
				if n == forbidden {
					t.Errorf("%s has forbidden actor-shaped field/tag %q", name, forbidden)
				}
			}
		}
	}
}

// TestNoExecutionIdentityField is half of T3: no exported request struct may
// carry an engine, engine_ref or execution_id field — the platform alone
// supplies execution identity.
func TestNoExecutionIdentityField(t *testing.T) {
	for name, typ := range requestStructs() {
		names := fieldNamesAndTags(typ)
		for _, forbidden := range forbiddenExecutionIdentityFields {
			for _, n := range names {
				if n == forbidden {
					t.Errorf("%s has forbidden execution-identity field/tag %q", name, forbidden)
				}
			}
		}
	}
}

// TestRouteAllowlist is the other half of T3: every path any client method
// can build must be one of the eight permitted routes, and none may contain
// a forbidden segment or be the bare list/PATCH route. Unlike a hardcoded
// literal slice, this actually calls all 8 Client methods against an
// httptest server and asserts the paths they build.
func TestRouteAllowlist(t *testing.T) {
	const id = "wi_123"
	const reqID = "xr_456"
	allowedPaths := map[string]bool{
		"/api/v1/surface-identities/redeem":                         true,
		"/api/v1/work-items":                                        true,
		"/api/v1/work-items/" + id:                                  true,
		"/api/v1/work-items/" + id + "/intents":                     true,
		"/api/v1/work-items/" + id + "/execution-requests":          true,
		"/api/v1/work-items/" + id + "/execution-requests/" + reqID: true,
		"/api/v1/work-items/" + id + "/surface-refs":                true,
	}
	forbiddenSubstrings := []string{"executions", "snapshot", "snapshots", "events", "approvals", "/resume"}

	var (
		pathMu  sync.Mutex
		gotPath string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathMu.Lock()
		gotPath = r.URL.Path
		pathMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/execution-requests") && r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"schema_version":"workitem/v1","execution_requests":[]}`))
			return
		}
		// Carries both an ItemView's work_item.id and an
		// ExecutionRequestView's id, so every route's validate() passes.
		_, _ = w.Write([]byte(`{"schema_version":"workitem/v1","id":"xr_1","work_item":{"id":"wi_1"},"state_version":1}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "surface-token", "tenant-1", nil)
	ctx := context.Background()
	observedMethods := make(map[string]bool)
	observedPaths := make(map[string]bool)

	check := func(callName string, err error) {
		t.Helper()
		pathMu.Lock()
		gotPath := gotPath
		pathMu.Unlock()
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", callName, err)
		}
		if !allowedPaths[gotPath] {
			t.Errorf("%s built path %q, not in the allowlist", callName, gotPath)
		}
		for _, f := range forbiddenSubstrings {
			if strings.Contains(gotPath, f) {
				t.Errorf("%s built path %q containing forbidden segment %q", callName, gotPath, f)
			}
		}
		observedMethods[callName] = true
		observedPaths[gotPath] = true
	}

	err := c.RedeemLink(ctx, 555, "CODE123")
	check("RedeemLink", err)

	_, err = c.CreateWorkItem(ctx, 555, CreateRequest{ExternalKey: "https://github.com/mctlhq/foo/issues/1"})
	check("CreateWorkItem", err)

	_, err = c.GetWorkItem(ctx, 555, id)
	check("GetWorkItem", err)

	err = c.AppendIntent(ctx, 555, id, IntentRequest{Text: "note"})
	check("AppendIntent", err)

	_, err = c.RequestExecution(ctx, 555, id, ExecutionRequest{Kind: ExecutionKindStart, ExpectedStateVersion: 1})
	check("RequestExecution", err)

	_, err = c.GetExecutionRequest(ctx, 555, id, reqID)
	check("GetExecutionRequest", err)

	_, err = c.ListExecutionRequests(ctx, 555, id)
	check("ListExecutionRequests", err)

	err = c.AddSurfaceRef(ctx, 555, id, SurfaceRefRequest{ChatTGID: 100, RootTGMessageID: 200})
	check("AddSurfaceRef", err)

	// 8 distinct methods, exercising all 7 distinct allowed routes (POST
	// .../execution-requests and GET .../execution-requests share one path,
	// distinguished only by HTTP method — RequestExecution and
	// ListExecutionRequests).
	const wantMethods = 8
	if len(observedMethods) != wantMethods {
		t.Errorf("observed %d distinct client methods, want %d (observed: %v)", len(observedMethods), wantMethods, observedMethods)
	}
	if len(observedPaths) != len(allowedPaths) {
		t.Errorf("observed %d distinct allowed paths, want %d (observed: %v)", len(observedPaths), len(allowedPaths), observedPaths)
	}
}

// TestHeaderDiscipline is T4: relay must send exactly the bearer, a
// digits-only X-MCTL-Surface-Actor, and Idempotency-Key on mutating calls,
// stable across a repeat; and origin_surface in the create body must always
// be "telegram" regardless of anything the caller could influence.
func TestHeaderDiscipline(t *testing.T) {
	var gotAuth, gotActor, gotIdem1, gotIdem2 string
	var gotBody map[string]any
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			gotAuth = r.Header.Get("Authorization")
			gotActor = r.Header.Get("X-MCTL-Surface-Actor")
			gotIdem1 = r.Header.Get("Idempotency-Key")
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
		} else {
			gotIdem2 = r.Header.Get("Idempotency-Key")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"workitem/v1","work_item":{"id":"wi_1"},"state_version":1}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "surface-token", "tenant-1", nil)
	idemKey := IdempotencyKey(555, 101, "open", 0)
	_, err := c.CreateWorkItem(context.Background(), 555, CreateRequest{ExternalKey: "https://github.com/mctlhq/foo/issues/1", IdempotencyKey: idemKey})
	if err != nil {
		t.Fatalf("CreateWorkItem: %v", err)
	}
	if gotAuth != "Bearer surface-token" {
		t.Errorf("Authorization = %q, want Bearer surface-token", gotAuth)
	}
	if gotActor != "555" {
		t.Errorf("X-MCTL-Surface-Actor = %q, want 555", gotActor)
	}
	for _, r := range gotActor {
		if r < '0' || r > '9' {
			t.Fatalf("X-MCTL-Surface-Actor = %q, not digits-only", gotActor)
		}
	}
	if gotIdem1 == "" {
		t.Error("Idempotency-Key missing on mutating call")
	}
	if gotBody["origin_surface"] != "telegram" {
		t.Errorf("origin_surface = %v, want telegram", gotBody["origin_surface"])
	}

	// Repeat: the key must be stable.
	_, err = c.CreateWorkItem(context.Background(), 555, CreateRequest{ExternalKey: "https://github.com/mctlhq/foo/issues/1", IdempotencyKey: idemKey})
	if err != nil {
		t.Fatalf("CreateWorkItem repeat: %v", err)
	}
	if gotIdem2 != gotIdem1 {
		t.Errorf("Idempotency-Key changed across retry: %q -> %q", gotIdem1, gotIdem2)
	}
}

// TestErrorMapping is T5: known mctl-api error codes map onto distinct
// sentinels.
func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		code   string
		want   error
	}{
		{403, "link_not_found", ErrLinkNotFound},
		{403, "link_revoked", ErrLinkRevoked},
		{403, "link_expired", ErrLinkExpired},
		{403, "relay_required", ErrRelayRequired},
		{400, "actor_not_accepted", ErrActorNotAccepted},
		{403, "challenge_invalid", ErrChallengeInvalid},
		{409, "link_conflict", ErrLinkConflict},
		{409, "state_version_conflict", ErrStateVersionConflict},
		{409, "external_key_in_use", ErrExternalKeyInUse},
		{409, "execution_request_open", ErrExecutionRequestOpen},
		{409, "execution_active", ErrExecutionActive},
		{409, "invalid_transition", ErrInvalidTransition},
	}
	for _, c := range cases {
		t.Run(c.code, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(`{"error":"` + c.code + `"}`))
			}))
			defer srv.Close()
			client := NewClient(srv.URL, "tok", "tenant", nil)
			err := client.RedeemLink(context.Background(), 555, "CODE123")
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want wrapping %v", err, c.want)
			}
		})
	}
}

// TestSchemaVersionRejection is T8: a response with an unexpected
// schema_version is rejected outright.
func TestSchemaVersionRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"workitem/v2","work_item":{"id":"wi_1"},"state_version":1}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "tok", "tenant", nil)
	_, err := client.GetWorkItem(context.Background(), 555, "wi_1")
	if err == nil {
		t.Fatal("expected schema rejection error")
	}
	if !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("err = %v, want ErrIncompatibleSchema", err)
	}
}

// TestOpenWorkItemResponseValidation locks in the fix for a P2 finding: a
// 2xx work-item response that decodes to a zero-value WorkItem.ID (either
// because the body is empty, or because it names schema_version correctly
// but omits work_item.id) must be rejected, not returned as a successful
// ItemView. Before the fix, relay() treated an empty body as success and
// GetWorkItem/CreateWorkItem happily returned a zero-value ItemView, which
// callers then persisted as a durable binding with an empty WorkItemID —
// wedging the owner's Saved Messages command channel on what looked like a
// permanently open binding.
func TestOpenWorkItemResponseValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"missing work_item.id", `{"schema_version":"workitem/v1","state_version":1}`},
		{"blank work_item.id", `{"schema_version":"workitem/v1","work_item":{"id":""},"state_version":1}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			client := NewClient(srv.URL, "tok", "tenant", nil)

			// Every malformed shape is one class: ErrIncompatibleSchema, so
			// the owner sees one message for one defect.
			if _, err := client.GetWorkItem(context.Background(), 555, "wi_1"); !errors.Is(err, ErrIncompatibleSchema) {
				t.Fatalf("GetWorkItem: err = %v, want ErrIncompatibleSchema", err)
			}

			if _, err := client.CreateWorkItem(context.Background(), 555, CreateRequest{ExternalKey: "https://github.com/mctlhq/foo/issues/1"}); !errors.Is(err, ErrIncompatibleSchema) {
				t.Fatalf("CreateWorkItem: err = %v, want ErrIncompatibleSchema", err)
			}
		})
	}
}

// TestOpenWorkItemResponseAccepted is the positive counterpart to
// TestOpenWorkItemResponseValidation: a 2xx response that does carry a
// non-empty work_item.id must still decode into a usable ItemView, so the
// new validate() hook only rejects the poison-pill shape, not every
// response.
func TestOpenWorkItemResponseAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"workitem/v1","work_item":{"id":"wi_1"},"state_version":3}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "tok", "tenant", nil)

	view, err := client.GetWorkItem(context.Background(), 555, "wi_1")
	if err != nil {
		t.Fatalf("GetWorkItem: unexpected error: %v", err)
	}
	if view.WorkItem.ID != "wi_1" {
		t.Errorf("WorkItem.ID = %q, want wi_1", view.WorkItem.ID)
	}
	if view.StateVersion != 3 {
		t.Errorf("StateVersion = %d, want 3", view.StateVersion)
	}
}

// TestExecutionRequestResponseValidation: a 2xx execution-request response
// without an id is rejected as ErrIncompatibleSchema — handleOpen and
// handleResume would otherwise persist and echo an empty request id.
func TestExecutionRequestResponseValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"workitem/v1","kind":"start","state":"pending"}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "tok", "tenant", nil)
	_, err := client.RequestExecution(context.Background(), 555, "wi_1", ExecutionRequest{Kind: ExecutionKindStart, IdempotencyKey: "k"})
	if !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("RequestExecution: err = %v, want ErrIncompatibleSchema", err)
	}
	if _, err := client.GetExecutionRequest(context.Background(), 555, "wi_1", "xr_1"); !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("GetExecutionRequest: err = %v, want ErrIncompatibleSchema", err)
	}
}

// TestListExecutionRequestsEmptyBody: an empty 2xx body (204 No Content) on
// the list route means "no requests", not an incompatible response — the
// list persists nothing, unlike the ItemView routes above.
func TestListExecutionRequestsEmptyBody(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusOK} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		client := NewClient(srv.URL, "tok", "tenant", nil)
		list, err := client.ListExecutionRequests(context.Background(), 555, "wi_1")
		srv.Close()
		if err != nil {
			t.Fatalf("status %d: unexpected error: %v", status, err)
		}
		if len(list) != 0 {
			t.Fatalf("status %d: list = %v, want empty", status, list)
		}
	}
}

// TestResponseBodyIsBounded: relay reads at most maxResponseBytes, so an
// oversized body is rejected as ErrIncompatibleSchema instead of being
// buffered whole.
func TestResponseBodyIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		pad := strings.Repeat("x", maxResponseBytes)
		_, _ = w.Write([]byte(`{"schema_version":"workitem/v1","work_item":{"id":"wi_1","title":"` + pad + `"},"state_version":1}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "tok", "tenant", nil)
	if _, err := client.GetWorkItem(context.Background(), 555, "wi_1"); !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("GetWorkItem: err = %v, want ErrIncompatibleSchema for a body over maxResponseBytes", err)
	}
}
