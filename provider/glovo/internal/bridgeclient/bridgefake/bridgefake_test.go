package bridgefake

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

const cred = "canary-bridge-credential"

type h struct {
	t *testing.T
	f *Fake
}

func newH(t *testing.T) *h {
	f := New()
	t.Cleanup(f.Close)
	f.AddProvider(cred, "provider:glovo", "tnr_0123456789abcdef0123")
	return &h{t, f}
}

func (x *h) post(path, auth string, body any) (int, map[string]any, http.Header) {
	x.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, x.f.URL()+"/api/v1/bridge/commands/"+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		x.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, resp.Header
}

func (x *h) claim() (token string, cmds []any, status int) {
	st, m, _ := x.post("claim", cred, map[string]int{"max": 4})
	if st != 200 {
		return "", nil, st
	}
	cmds, _ = m["commands"].([]any)
	if len(cmds) > 0 {
		token, _ = cmds[0].(map[string]any)["lease_token"].(string)
	}
	return token, cmds, st
}

func result(id, tok, outcome, effect string) map[string]any {
	r := map[string]any{"schema_version": "bridge.mctl.ai/v1alpha1", "command_id": id, "execution_id": "we_0123456789abcdef0123",
		"lease_token": tok, "attempt": 1, "worker_identity": "provider:glovo", "outcome": outcome, "provider_effect": effect,
		"completed_at": "2026-11-08T10:01:00Z"}
	return r
}

func TestAuthTenantAndAudience(t *testing.T) {
	x := newH(t)
	if st, m, _ := x.post("claim", "wrong", nil); st != 401 || m["code"] != nil {
		t.Fatalf("401 must be code-less: %d %v", st, m)
	}
	foreign := Command("quote")
	foreign["tenant_ref"] = "tnr_otherotherother0000"
	wrongAud := Command("quote")
	wrongAud["audience"] = "provider:other"
	own := Command("quote")
	idF, idA, idO := x.f.Enqueue(foreign), x.f.Enqueue(wrongAud), x.f.Enqueue(own)
	_, cmds, _ := x.claim()
	if len(cmds) != 1 || cmds[0].(map[string]any)["command_id"] != idO {
		t.Fatalf("only the own command may be claimed: %v", cmds)
	}
	for _, id := range []string{idF, idA} {
		if st, m, _ := x.post(id+"/write-permit", cred, map[string]string{"lease_token": "lt_x"}); st != 404 || m["code"] != "command_not_found" {
			t.Fatalf("permit on foreign: %d %v", st, m)
		}
		if st, m, _ := x.post(id+"/result", cred, result(id, "lt_0123456789abcdef", "succeeded", "none")); st != 404 || m["code"] != "command_not_found" {
			t.Fatalf("result on foreign: %d %v", st, m)
		}
	}
}

func TestLeaseReclaimEpochAndStaleHolder(t *testing.T) {
	x := newH(t)
	x.f.SetLeaseTTL(250 * time.Millisecond)
	id := x.f.Enqueue(Command("quote"))
	tok1, cmds, _ := x.claim()
	if len(cmds) != 1 {
		t.Fatal("claim")
	}
	if _, c2, _ := x.claim(); len(c2) != 0 {
		t.Fatal("a live lease must not be re-claimed")
	}
	time.Sleep(300 * time.Millisecond)
	tok2, cmds, _ := x.claim()
	if len(cmds) != 1 || tok2 == tok1 {
		t.Fatalf("reclaim must give a new token: %q %q", tok1, tok2)
	}
	if _, _, ep := x.f.State(id); ep != 1 {
		t.Fatalf("epoch = %d", ep)
	}
	if st, m, _ := x.post(id+"/result", cred, result(id, tok1, "succeeded", "none")); st != 409 || m["code"] != "lease_stale" {
		t.Fatalf("old holder: %d %v", st, m)
	}
	if st, _, _ := x.post(id+"/result", cred, result(id, tok2, "succeeded", "none")); st != 200 {
		t.Fatalf("new holder: %d", st)
	}
}

func TestExpiresAtAndCancel(t *testing.T) {
	x := newH(t)
	exp := Command("quote")
	exp["expires_at"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	x.f.Enqueue(exp)
	if _, cmds, _ := x.claim(); len(cmds) != 0 {
		t.Fatal("an expired command must not be claimed")
	}
	id := x.f.Enqueue(Command("quote"))
	tok, _, _ := x.claim()
	x.f.Cancel(id)
	if st, m, _ := x.post(id+"/result", cred, result(id, tok, "succeeded", "none")); st != 409 || m["code"] != "command_cancelled" {
		t.Fatalf("cancelled: %d %v", st, m)
	}
}

func TestPermitModesAndRules(t *testing.T) {
	x := newH(t)
	q := x.f.Enqueue(Command("quote"))
	tq, _, _ := x.claim()
	if st, m, _ := x.post(q+"/write-permit", cred, map[string]string{"lease_token": tq}); st != 409 || m["code"] != "not_mutating" {
		t.Fatalf("not_mutating: %d %v", st, m)
	}
	id := x.f.Enqueue(Command("place_order_fake"))
	tok, _, _ := x.claim()
	x.f.SetPermitMode(PermitRefuse)
	if st, m, _ := x.post(id+"/write-permit", cred, map[string]string{"lease_token": tok}); st != 403 || m["code"] != "write_fence_refused" {
		t.Fatalf("refuse: %d %v", st, m)
	}
	x.f.SetPermitMode(PermitUnavailable)
	if st, m, _ := x.post(id+"/write-permit", cred, map[string]string{"lease_token": tok}); st != 503 || m["code"] != "write_fence_unavailable" {
		t.Fatalf("unavailable: %d %v", st, m)
	}
	x.f.SetPermitMode(PermitAllow)
	if st, _, _ := x.post(id+"/write-permit", cred, map[string]string{"lease_token": tok}); st != 200 {
		t.Fatalf("allow: %d", st)
	}
	// Effect rule 3: a permit when effect_state != none.
	if st, m, _ := x.post(id+"/write-permit", cred, map[string]string{"lease_token": tok}); st != 409 || m["code"] != "permit_already_issued" {
		t.Fatalf("second permit: %d %v", st, m)
	}
}

func TestEffectRules(t *testing.T) {
	// Rule 2: applied without permitted is 422.
	x := newH(t)
	id := x.f.Enqueue(Command("place_order_fake"))
	tok, _, _ := x.claim()
	if st, m, _ := x.post(id+"/result", cred, result(id, tok, "succeeded", "applied")); st != 422 || m["code"] != "result_inconsistent" {
		t.Fatalf("applied without permit: %d %v", st, m)
	}
	// approval_refused requires effect none.
	if st, m, _ := x.post(id+"/result", cred, result(id, tok, "approval_refused", "unknown")); st != 422 {
		t.Fatalf("approval_refused with effect: %d %v", st, m)
	}
	// Rule 1a: reclaim turns permitted into unknown.
	y := newH(t)
	y.f.SetLeaseTTL(250 * time.Millisecond)
	id = y.f.Enqueue(Command("place_order_fake"))
	tok, _, _ = y.claim()
	y.post(id+"/write-permit", cred, map[string]string{"lease_token": tok})
	time.Sleep(300 * time.Millisecond)
	tok2, _, _ := y.claim()
	if _, eff, _ := y.f.State(id); eff != EffectUnknown {
		t.Fatalf("reclaim: effect = %s", eff)
	}
	if st, _, _ := y.post(id+"/result", cred, result(id, tok2, "succeeded", "applied")); st != 422 {
		t.Fatalf("applied after reclaim must be 422, got %d", st)
	}
	// Rule 1b: cancel turns permitted into unknown.
	z := newH(t)
	id = z.f.Enqueue(Command("place_order_fake"))
	tok, _, _ = z.claim()
	z.post(id+"/write-permit", cred, map[string]string{"lease_token": tok})
	z.f.Cancel(id)
	if _, eff, _ := z.f.State(id); eff != EffectUnknown {
		t.Fatalf("cancel: effect = %s", eff)
	}
}

func TestResultValidationBindingReplayConflict(t *testing.T) {
	x := newH(t)
	id := x.f.Enqueue(Command("quote"))
	tok, _, _ := x.claim()
	bad := result(id, tok, "succeeded", "none")
	bad["extra"] = 1
	if st, m, _ := x.post(id+"/result", cred, bad); st != 400 || m["code"] != "invalid_document" {
		t.Fatalf("schema: %d %v", st, m)
	}
	for k, v := range map[string]any{"worker_identity": "provider:evil", "execution_id": "we_ffffffffffffffffffff", "attempt": 2} {
		r := result(id, tok, "succeeded", "none")
		r[k] = v
		if st, m, _ := x.post(id+"/result", cred, r); st != 409 || m["code"] != "binding_mismatch" {
			t.Fatalf("binding %s: %d %v", k, st, m)
		}
	}
	good := result(id, tok, "succeeded", "none")
	if st, m, _ := x.post(id+"/result", cred, good); st != 200 || m["replayed"] != false {
		t.Fatalf("first: %d %v", st, m)
	}
	// Replay, also after the lease ran out.
	x.f.ExpireLease(id)
	if st, m, _ := x.post(id+"/result", cred, good); st != 200 || m["replayed"] != true {
		t.Fatalf("replay: %d %v", st, m)
	}
	other := result(id, tok, "failed_retryable", "none")
	if st, m, _ := x.post(id+"/result", cred, other); st != 409 || m["code"] != "result_conflict" {
		t.Fatalf("conflict: %d %v", st, m)
	}
}

func TestFaultsClaimBodiesAndRecorder(t *testing.T) {
	x := newH(t)
	x.f.FailNext("claim", Fault{Status: 429, Body: "slow down", RetryAfter: "7"})
	if st, m, hd := x.post("claim", cred, nil); st != 429 || m != nil || hd.Get("Retry-After") != "7" {
		t.Fatalf("429: %d %v %v", st, m, hd)
	}
	id := x.f.Enqueue(Command("quote"))
	tok, _, _ := x.claim()
	x.f.FailNext("result", Fault{Status: 503, AfterStore: true})
	good := result(id, tok, "succeeded", "none")
	if st, _, _ := x.post(id+"/result", cred, good); st != 503 {
		t.Fatal("after-store fault")
	}
	if st, m, _ := x.post(id+"/result", cred, good); st != 200 || m["replayed"] != true {
		t.Fatalf("after-store must have stored: %d %v", st, m)
	}
	x.f.SetClaimBody([]byte(`{"schema_version":"bridge.mctl.ai/v1alpha1"}`))
	if _, m, _ := x.post("claim", cred, nil); m["commands"] != nil {
		t.Fatal("claim body override")
	}
	if x.f.Count("claim") != 3 || x.f.Count("result") != 2 {
		t.Fatalf("counts: %d %d", x.f.Count("claim"), x.f.Count("result"))
	}
	var seenAuth bool
	for _, r := range x.f.Requests() {
		if r.Authorization == "Bearer "+cred {
			seenAuth = true
		}
		if strings.Contains(string(r.Body), cred) {
			t.Fatal("credential in a body")
		}
	}
	if !seenAuth {
		t.Fatal("recorder lost the Authorization header")
	}
	if len(x.f.ResultBodies()) != 2 {
		t.Fatal("result bodies")
	}
}

func TestGoldenCommandsAreSchemaValid(t *testing.T) {
	for _, d := range []map[string]any{Command("quote"), Command("place_order_fake"), Command("cancel_order_fake"), Command("read_status"), PlaceOrderV2()} {
		b, _ := json.Marshal(d)
		if _, _, err := v1alpha1.ParseCommand(b); err != nil {
			t.Fatalf("%v: %v", d["kind"], err)
		}
	}
}
