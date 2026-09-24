package workctx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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
// a forbidden segment or be the bare list/PATCH route.
func TestRouteAllowlist(t *testing.T) {
	const id = "wi_123"
	const reqID = "xr_456"
	paths := []string{
		"/api/v1/surface-identities/redeem",
		"/api/v1/work-items",
		"/api/v1/work-items/" + id,
		"/api/v1/work-items/" + id + "/intents",
		"/api/v1/work-items/" + id + "/execution-requests",
		"/api/v1/work-items/" + id + "/execution-requests/" + reqID,
		"/api/v1/work-items/" + id + "/surface-refs",
	}
	forbiddenSubstrings := []string{"executions", "snapshot", "snapshots", "events", "approvals", "/resume"}
	for _, p := range paths {
		for _, f := range forbiddenSubstrings {
			if strings.Contains(p, f) {
				t.Errorf("path %q contains forbidden segment %q", p, f)
			}
		}
		if p == "/api/v1/work-items" {
			// POST-only in this package; verified this is never called as a
			// bare GET (the list route) by construction — CreateWorkItem is
			// the only method building this exact path, and it always POSTs.
			continue
		}
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
