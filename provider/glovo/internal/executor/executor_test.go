package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakestore"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

func api(status int, code string) error { return &bridgeclient.APIError{Status: status, Code: code} }

func TestEveryTableRowBuildsAValidResult(t *testing.T) {
	e := &Executor{WorkerIdentity: "provider:glovo", Now: func() time.Time { return time.Date(2026, 11, 8, 10, 1, 0, 0, time.UTC) }}
	id := v1alpha1.Envelope{CommandID: "cmd_01HZZZZZZZZZZZZZZZZZZZZZZZ", ExecutionID: "we_0123456789abcdef0123", LeaseToken: "lt_0123456789abcdef0123", Attempt: 1}
	seen := map[Situation]bool{}
	for _, row := range Table {
		if seen[row.Situation] {
			t.Fatalf("duplicate situation %s", row.Situation)
		}
		seen[row.Situation] = true
		res, err := e.Build(row.Situation, id, "")
		if row.Outcome == "" {
			if err == nil {
				t.Errorf("%s: a row without an outcome must not build a result", row.Situation)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", row.Situation, err)
			continue
		}
		if res.Outcome != row.Outcome || res.ErrorCode != row.ErrorCode || res.ProviderEffect != row.Effect || res.ErrorDetail != row.Detail {
			t.Errorf("%s: result %+v does not follow its row", row.Situation, res)
		}
		if _, err := v1alpha1.EncodeResult(res); err != nil {
			t.Errorf("%s: result is not schema-valid: %v", row.Situation, err)
		}
		if (row.Situation == SitReadOK || row.Situation == SitApplied) != (res.ResultRef != "") {
			t.Errorf("%s: result_ref only on the success rows", row.Situation)
		}
	}
	// The effect rules of mctl-api: unknown never reports applied after a reclaim.
	for _, s := range []Situation{SitAppliedPriorLease, SitPermitAlready, SitAmbiguousWrite} {
		if r, _ := RowFor(s); r.Effect != v1alpha1.EffectUnknown {
			t.Errorf("%s must report effect unknown", s)
		}
	}
	// A schema failure keeps an override detail.
	if res, _ := e.Build(SitSchemaInvalid, id, "audience_mismatch"); res.ErrorDetail != "audience_mismatch" {
		t.Error("detail override")
	}
}

func TestClassifyPermit(t *testing.T) {
	for _, c := range []struct {
		err  error
		want Situation
	}{
		{api(403, "write_fence_refused"), SitPermitRefused},
		{api(503, "write_fence_unavailable"), SitPermitFenceDown},
		{api(409, "permit_already_issued"), SitPermitAlready},
		{api(409, "not_mutating"), SitPermitNotMutating},
		{api(429, ""), SitPermit429},
		{api(429, "rate_limited"), SitPermit429},
		{api(500, "bridge_internal"), SitPermitTransient},
		{api(503, "bridge_unavailable"), SitPermitTransient},
		{api(502, ""), SitPermitTransient},
		{errors.New("boom"), SitPermitTransient},
		{context.DeadlineExceeded, SitPermitTransient},
		{api(409, "lease_stale"), SitStop},
		{api(409, "command_expired"), SitStop},
		{api(409, "command_cancelled"), SitStop},
		{api(404, "command_not_found"), SitNotFound},
		{api(401, ""), SitUnauthorized},
		{api(401, "something"), SitUnmapped},
		{api(418, ""), SitUnmapped},
		{api(400, "invalid_input"), SitUnmapped},
		{api(404, ""), SitUnmapped},
		{bridgeclient.ErrOrigin, SitUnmapped},
		{bridgeclient.ErrMalformed, SitUnmapped},
	} {
		if got := ClassifyPermit(c.err); got != c.want {
			t.Errorf("%v: got %s want %s", c.err, got, c.want)
		}
	}
}

func TestClassifyResult(t *testing.T) {
	for _, c := range []struct {
		err  error
		want Situation
	}{
		{api(409, "already_completed"), SitResultAlreadyDone},
		{api(409, "result_conflict"), SitResultConflict},
		{api(400, "invalid_document"), SitResultBug},
		{api(409, "binding_mismatch"), SitResultBug},
		{api(422, "result_inconsistent"), SitResultBug},
		{api(500, ""), SitResultRetry},
		{api(503, "write_fence_unavailable"), SitResultRetry},
		{api(429, ""), SitResultRetry},
		{errors.New("eof"), SitResultRetry},
		{api(409, "lease_stale"), SitStop},
		{api(409, "command_expired"), SitStop},
		{api(409, "command_cancelled"), SitStop},
		{api(404, "command_not_found"), SitNotFound},
		{api(401, ""), SitUnauthorized},
		{api(418, "x"), SitUnmapped},
		{api(403, "write_fence_refused"), SitUnmapped},
		{bridgeclient.ErrMalformed, SitUnmapped},
	} {
		if got := ClassifyResult(c.err); got != c.want {
			t.Errorf("%v: got %s want %s", c.err, got, c.want)
		}
	}
}

func TestClassifyClaim(t *testing.T) {
	if s, nr := ClassifyClaim(api(429, "")); s != SitClaim429 || nr {
		t.Errorf("429: %s %v", s, nr)
	}
	for _, st := range []int{401, 403, 404} {
		if _, nr := ClassifyClaim(api(st, "")); !nr {
			t.Errorf("%d must keep readiness failing", st)
		}
	}
	if _, nr := ClassifyClaim(api(500, "")); nr {
		t.Error("5xx is not a refusal")
	}
}

func TestReadAndWritePaths(t *testing.T) {
	store := fakestore.New()
	e := &Executor{Store: store, WorkerIdentity: "provider:glovo"}
	ctx := context.Background()
	mk := func(kind, id string) v1alpha1.Command {
		n := 1
		return v1alpha1.Command{CommandID: id, Kind: kind, TenantRef: "tnr_a", ConnectionRef: "gcn_a", OrderRef: "ordr_a",
			Payload: v1alpha1.Payload{ItemCodes: []string{"FAKE-1", "FAKE-2"}, QuantityTotal: &n}}
	}
	if s := e.RunRead(ctx, mk("quote", "cmd_q")); s != SitReadOK {
		t.Fatalf("quote: %s", s)
	}
	bad := mk("quote", "cmd_q2")
	bad.Payload.ItemCodes = []string{"NOPE"}
	if s := e.RunRead(ctx, bad); s != SitStoreRejected {
		t.Fatalf("unknown item: %s", s)
	}
	if s := e.RunRead(ctx, mk("read_status", "cmd_s")); s != SitReadOK {
		t.Fatalf("read_status: %s", s)
	}
	store.SetTransientReads(1)
	if s := e.RunRead(ctx, mk("quote", "cmd_q3")); s != SitStoreTransient {
		t.Fatalf("transient: %s", s)
	}
	// Write, then dedupe, then cancel.
	place := mk("place_order_fake", "cmd_p")
	if e.HasPriorEffect(place) {
		t.Fatal("no prior effect yet")
	}
	if s := e.RunWrite(ctx, place); s != SitApplied {
		t.Fatalf("place: %s", s)
	}
	if !e.HasPriorEffect(place) {
		t.Fatal("effect record expected")
	}
	if s := e.RunWrite(ctx, mk("cancel_order_fake", "cmd_c")); s != SitApplied {
		t.Fatalf("cancel: %s", s)
	}
	if s := e.RunWrite(ctx, mk("cancel_order_fake", "cmd_c2")); s != SitStoreRejected {
		t.Fatalf("second cancel has no order to cancel: %s", s)
	}
	// Revoked session.
	store.Revoke(SessionKey(place))
	if s := e.RunWrite(ctx, mk("place_order_fake", "cmd_p2")); s != SitStoreRejected {
		t.Fatalf("revoked: %s", s)
	}
	if s := e.RunWrite(ctx, mk("quote", "x")); s != SitUnmapped {
		t.Fatalf("a read kind is not a write: %s", s)
	}
}
