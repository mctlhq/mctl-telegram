package poller

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient/bridgefake"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/executor"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fairness"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakestore"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/health"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/leakcheck"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/obs"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

var canary = leakcheck.Canaries[0]

const tenant = "tnr_0123456789abcdef0123"

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type rig struct {
	t        *testing.T
	f        *bridgefake.Fake
	store    *fakestore.Store
	m        *obs.Metrics
	logs     *syncBuf
	p        *Poller
	disabled atomic.Bool
	breaker  *fairness.Breaker
	cancel   context.CancelFunc
	done     chan struct{}
	credFile string
}

func newRig(t *testing.T, tweak ...func(*Config)) *rig {
	t.Helper()
	r := &rig{t: t, f: bridgefake.New(), store: fakestore.New(), m: obs.NewMetrics(), logs: &syncBuf{}, breaker: fairness.NewBreaker(1)}
	t.Cleanup(r.f.Close)
	r.f.AddProvider(canary, "provider:glovo", tenant)
	r.credFile = filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(r.credFile, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origin, err := bridgeclient.ParseOrigin(r.f.URL())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{PollInterval: 15 * time.Millisecond, ClaimBackoffCap: 100 * time.Millisecond,
		ResultBackoffMin: 10 * time.Millisecond, ResultBackoffMax: 40 * time.Millisecond, StopTimeout: 2 * time.Second}
	for _, f := range tweak {
		f(&cfg)
	}
	log := slog.New(obs.NewRedactingHandler(slog.NewTextHandler(r.logs, nil)))
	r.p = &Poller{
		Client: bridgeclient.New(origin, bridgeclient.FileCredential{Path: r.credFile}, nil),
		Exec: &executor.Executor{Store: r.store, Breaker: r.breaker, Disabled: r.disabled.Load, Metrics: r.m,
			WorkerIdentity: "provider:glovo"},
		Limiter: fairness.NewLimiter(4), Health: &health.State{Window: time.Minute}, Metrics: r.m, Log: log, Cfg: cfg,
	}
	return r
}

func (r *rig) start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel, r.done = cancel, make(chan struct{})
	go func() { _ = r.p.Run(ctx); close(r.done) }()
	r.t.Cleanup(r.stop)
}

func (r *rig) stop() {
	if r.cancel != nil {
		r.cancel()
		<-r.done
		r.cancel = nil
	}
}

func (r *rig) waitFor(what string, cond func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatalf("timed out waiting for %s", what)
}

func (r *rig) settle() { time.Sleep(150 * time.Millisecond) }

func (r *rig) results(id string) []v1alpha1.Result {
	var out []v1alpha1.Result
	for _, b := range r.f.ResultBodies() {
		var res v1alpha1.Result
		if json.Unmarshal(b, &res) == nil && res.CommandID == id {
			out = append(out, res)
		}
	}
	return out
}

func (r *rig) result(id string) v1alpha1.Result {
	r.t.Helper()
	r.waitFor("a result for "+id, func() bool { return len(r.results(id)) > 0 })
	return r.results(id)[0]
}

func (r *rig) writes() int { _, w := r.store.Counts(); return w }

func (r *rig) metric(name string, labels ...string) float64 {
	r.t.Helper()
	fams, err := r.m.Registry.Gather()
	if err != nil {
		r.t.Fatal(err)
	}
	var sum float64
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			match := true
			for i := 0; i+1 < len(labels); i += 2 {
				found := false
				for _, l := range m.GetLabel() {
					if l.GetName() == labels[i] && l.GetValue() == labels[i+1] {
						found = true
					}
				}
				match = match && found
			}
			if match {
				sum += m.GetCounter().GetValue() + m.GetGauge().GetValue()
			}
		}
	}
	return sum
}

func (r *rig) expect(res v1alpha1.Result, outcome, effect, code string) {
	r.t.Helper()
	if res.Outcome != outcome || res.ProviderEffect != effect || res.ErrorCode != code {
		r.t.Fatalf("result = %s/%s/%s, want %s/%s/%s (detail %q)", res.Outcome, res.ProviderEffect, res.ErrorCode, outcome, effect, code, res.ErrorDetail)
	}
}

func raw(d map[string]any) json.RawMessage { b, _ := json.Marshal(d); return b }

func withLease(d map[string]any) map[string]any {
	d["lease_token"] = "lt_forcedforcedforced0000"
	return d
}

// T5: happy path for each kind.
func TestHappyPathPerKind(t *testing.T) {
	r := newRig(t)
	q := r.f.Enqueue(bridgefake.Command("quote"))
	place := bridgefake.Command("place_order_fake")
	p := r.f.Enqueue(place)
	r.start()
	r.expect(r.result(q), "succeeded", "none", "none")
	r.expect(r.result(p), "succeeded", "applied", "none")
	// read_status reads the fake order of order_ref: a placed order succeeds,
	// an order that does not exist is a rejection, not a silent success.
	status := bridgefake.Command("read_status")
	status["order_ref"] = place["order_ref"]
	s := r.f.Enqueue(status)
	r.expect(r.result(s), "succeeded", "none", "none")
	unknown := bridgefake.Command("read_status")
	unknown["order_ref"] = "ordr_0000000000000000none"
	u := r.f.Enqueue(unknown)
	r.expect(r.result(u), "failed_terminal", "none", "provider_rejected")
	if r.f.Count("permit") != 1 {
		t.Fatalf("permit calls = %d after place", r.f.Count("permit"))
	}
	cancel := bridgefake.Command("cancel_order_fake")
	cancel["order_ref"] = place["order_ref"]
	c := r.f.Enqueue(cancel)
	r.expect(r.result(c), "succeeded", "applied", "none")
	if r.f.Count("permit") != 2 || r.writes() != 2 {
		t.Fatalf("permits = %d writes = %d", r.f.Count("permit"), r.writes())
	}
	if st, _ := r.store.OrderStatus(place["order_ref"].(string)); st != fakestore.StatusCancelled {
		t.Fatalf("order status = %q", st)
	}
	if r.result(p).ResultRef == "" || r.result(q).ResultRef != executor.ResultRef(q) {
		t.Fatal("result_ref must be the deterministic res_ id")
	}
}

// T3: a schema-invalid command is never executed.
func TestSchemaInvalidCommand(t *testing.T) {
	r := newRig(t)
	bad := bridgefake.Command("place_order_fake")
	bad["order_ref"] = "not-an-order-ref"
	withLease(bad)
	r.f.ForceClaim(raw(bad))
	// No usable envelope: no result, a dropped metric.
	r.f.ForceClaim(json.RawMessage(`{"kind":"place_order_fake","command_id":"x"}`))
	r.start()
	res := r.result(bad["command_id"].(string))
	r.expect(res, "failed_terminal", "none", "provider_rejected")
	if res.ErrorDetail != "schema_invalid" {
		t.Fatalf("detail = %q", res.ErrorDetail)
	}
	r.waitFor("dropped metric", func() bool {
		return r.metric("mctl_glovo_provider_commands_dropped_total", "reason", "schema_invalid") == 1
	})
	r.settle()
	if r.writes() != 0 || r.f.Count("permit") != 0 || r.f.Count("result") != 1 {
		t.Fatalf("writes=%d permits=%d results=%d", r.writes(), r.f.Count("permit"), r.f.Count("result"))
	}
}

// T6 (local half): a claimed command for another audience is refused.
func TestAudienceMismatchRefusedLocally(t *testing.T) {
	r := newRig(t)
	d := withLease(bridgefake.Command("place_order_fake"))
	d["audience"] = "provider:other"
	r.f.ForceClaim(raw(d))
	r.start()
	r.waitFor("result attempt", func() bool { return r.f.Count("result") == 1 })
	var body v1alpha1.Result
	_ = json.Unmarshal(r.f.ResultBodies()[0], &body)
	if body.ErrorDetail != "audience_mismatch" || body.ProviderEffect != "none" {
		t.Fatalf("body = %+v", body)
	}
	r.settle()
	if r.writes() != 0 || r.f.Count("permit") != 0 {
		t.Fatal("no permit and no effect expected")
	}
}

// T6 (server half): foreign tenant and wrong audience are never claimed.
func TestForeignTenantNeverClaimed(t *testing.T) {
	r := newRig(t)
	d := bridgefake.Command("quote")
	d["tenant_ref"] = "tnr_foreignforeignforeign"
	id := r.f.Enqueue(d)
	r.start()
	r.settle()
	if len(r.results(id)) != 0 || r.f.Count("claim") < 2 {
		t.Fatal("foreign command must not be handled")
	}
}

// T7: a reclaim mid-execution makes the old holder stale; no second effect.
func TestStaleLeaseAfterReclaim(t *testing.T) {
	r := newRig(t)
	r.f.SetReclaimAfterPermit(true)
	r.f.SetLeaseTTL(time.Hour)
	id := r.f.Enqueue(bridgefake.Command("place_order_fake"))
	r.start()
	r.waitFor("stale result", func() bool { return r.f.Count("result") == 1 })
	r.settle()
	if r.f.Count("result") != 1 || r.writes() != 1 {
		t.Fatalf("results=%d writes=%d", r.f.Count("result"), r.writes())
	}
	if _, eff, ep := r.f.State(id); eff != bridgefake.EffectUnknown || ep != 1 {
		t.Fatalf("effect=%s epoch=%d", eff, ep)
	}
	if r.metric("mctl_glovo_provider_commands_dropped_total", "reason", "lease_lost") != 1 {
		t.Fatal("stop must be counted")
	}
}

// T8 and T9: the same bytes are resent; the command is never re-executed.
func TestResultReplayAndRetries(t *testing.T) {
	r := newRig(t)
	r.f.FailNext("result", bridgefake.Fault{Status: 503, AfterStore: true})
	id := r.f.Enqueue(bridgefake.Command("place_order_fake"))
	r.start()
	r.waitFor("two result posts", func() bool { return r.f.Count("result") == 2 })
	r.settle()
	bodies := r.f.ResultBodies()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("the retry must carry identical bytes")
	}
	if r.writes() != 1 || r.f.Count("permit") != 1 {
		t.Fatalf("writes=%d permits=%d", r.f.Count("permit"), r.writes())
	}
	if st, _, _ := r.f.State(id); st != bridgefake.StatusCompleted {
		t.Fatalf("status = %s", st)
	}
	if r.metric("mctl_glovo_provider_results_total", "status", "replayed") != 1 {
		t.Fatal("replayed:true must be counted")
	}
}

func TestResult5xxRetriedUntilSuccessAndStopsAtExpiry(t *testing.T) {
	r := newRig(t)
	r.f.FailNext("result", bridgefake.Fault{Status: 500}, bridgefake.Fault{Status: 502, Body: "<html>"}, bridgefake.Fault{Status: 429, RetryAfter: "0"})
	id := r.f.Enqueue(bridgefake.Command("quote"))
	r.start()
	r.waitFor("success after 3 faults", func() bool { return r.f.Count("result") == 4 })
	if len(r.results(id)) != 4 {
		t.Fatal("same command, four posts")
	}
	r.stop()

	// A command whose expires_at is near: retries end at expires_at.
	r2 := newRig(t)
	for i := 0; i < 500; i++ {
		r2.f.FailNext("result", bridgefake.Fault{Status: 503})
	}
	d := bridgefake.Command("quote")
	d["expires_at"] = time.Now().Add(700 * time.Millisecond).UTC().Format("2006-01-02T15:04:05.999999999Z")
	r2.f.Enqueue(d)
	r2.start()
	r2.waitFor("some retries", func() bool { return r2.f.Count("result") >= 3 })
	time.Sleep(900 * time.Millisecond)
	n := r2.f.Count("result")
	time.Sleep(200 * time.Millisecond)
	if r2.f.Count("result") != n {
		t.Fatal("retries must stop at expires_at")
	}
}

// T10: result_conflict is counted, not resent, and logs the code only.
func TestResultConflict(t *testing.T) {
	r := newRig(t)
	r.f.FailNext("result", bridgefake.Fault{Status: 409, Body: `{"error":"x","code":"result_conflict"}`})
	id := r.f.Enqueue(bridgefake.Command("quote"))
	r.start()
	r.waitFor("conflict metric", func() bool { return r.metric("mctl_glovo_provider_result_conflicts_total") == 1 })
	r.settle()
	if len(r.results(id)) != 1 {
		t.Fatalf("no resend after conflict, got %d posts", len(r.results(id)))
	}
	if !strings.Contains(r.logs.String(), "result_conflict") {
		t.Fatal("log must carry the code")
	}
}

// T11: a refused permit means zero effects and the mapped result.
func TestPermitRefusals(t *testing.T) {
	cases := []struct {
		name            string
		prep            func(*rig)
		outcome, effect string
		code, detail    string
	}{
		{"write_fence_refused", func(r *rig) { r.f.SetPermitMode(bridgefake.PermitRefuse) }, "approval_refused", "none", "approval_refused", ""},
		{"write_fence_unavailable", func(r *rig) { r.f.SetPermitMode(bridgefake.PermitUnavailable) }, "failed_retryable", "none", "internal", "write_fence_unavailable"},
		{"permit_already_issued", func(r *rig) {
			r.f.FailNext("permit", bridgefake.Fault{Status: 409, Body: `{"error":"x","code":"permit_already_issued"}`})
		}, "failed_terminal", "unknown", "internal", "permit_already_issued"},
		{"not_mutating", func(r *rig) {
			r.f.FailNext("permit", bridgefake.Fault{Status: 409, Body: `{"error":"x","code":"not_mutating"}`})
		}, "failed_terminal", "none", "internal", "not_mutating"},
		{"429", func(r *rig) { r.f.FailNext("permit", bridgefake.Fault{Status: 429, RetryAfter: "3"}) }, "failed_retryable", "none", "provider_unavailable", ""},
		{"5xx", func(r *rig) { r.f.FailNext("permit", bridgefake.Fault{Status: 500, Body: "oops"}) }, "failed_retryable", "none", "provider_unavailable", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.prep(r)
			id := r.f.Enqueue(bridgefake.Command("place_order_fake"))
			r.start()
			res := r.result(id)
			r.expect(res, c.outcome, c.effect, c.code)
			if res.ErrorDetail != c.detail {
				t.Fatalf("detail = %q", res.ErrorDetail)
			}
			if r.writes() != 0 {
				t.Fatal("zero effects expected")
			}
		})
	}
}

// T12: ambiguous writes.
func TestAmbiguousWrite(t *testing.T) {
	r := newRig(t)
	r.store.SetWriteLostOnce()
	id := r.f.Enqueue(bridgefake.Command("place_order_fake"))
	r.start()
	r.expect(r.result(id), "failed_terminal", "unknown", "provider_unavailable")
	r.settle()
	if r.writes() != 1 || r.metric("mctl_glovo_provider_ambiguous_writes_total") != 1 {
		t.Fatalf("writes = %d", r.writes())
	}
	r.stop()

	r2 := newRig(t)
	r2.store.SetWriteTimeoutOnce()
	id = r2.f.Enqueue(bridgefake.Command("place_order_fake"))
	r2.start()
	r2.expect(r2.result(id), "succeeded", "applied", "none")
	if r2.metric("mctl_glovo_provider_ambiguous_writes_total") != 0 {
		t.Fatal("a confirmed timeout-after-apply is not ambiguous")
	}
}

// T13: re-delivery after a reclaim reports unknown and never applied.
func TestRedeliveryAfterReclaim(t *testing.T) {
	r := newRig(t)
	r.f.SetReclaimAfterPermit(true)
	r.f.SetLeaseTTL(400 * time.Millisecond)
	id := r.f.Enqueue(bridgefake.Command("place_order_fake"))
	r.start()
	r.waitFor("first stale result", func() bool { return r.f.Count("result") == 1 })
	r.f.SetReclaimAfterPermit(false)
	r.waitFor("redelivery result", func() bool { return r.f.Count("result") == 2 })
	res := r.results(id)[1]
	r.expect(res, "failed_terminal", "unknown", "internal")
	if res.ErrorDetail != "applied_prior_lease" {
		t.Fatalf("detail = %q", res.ErrorDetail)
	}
	r.settle()
	if r.f.Count("permit") != 1 || r.writes() != 1 {
		t.Fatalf("permits=%d writes=%d", r.f.Count("permit"), r.writes())
	}
	if st, eff, _ := r.f.State(id); st != bridgefake.StatusCompleted || eff != bridgefake.EffectUnknown {
		t.Fatalf("the fake must accept the result: %s %s", st, eff)
	}
}

// T14: cancel and expiry produce no effect.
func TestCancelAndExpiry(t *testing.T) {
	r := newRig(t)
	d := bridgefake.Command("place_order_fake")
	d["cancel_requested"] = true
	id := r.f.Enqueue(d)
	exp := withLease(bridgefake.Command("place_order_fake"))
	exp["expires_at"] = "2020-01-01T00:00:00Z"
	r.f.ForceClaim(raw(exp))
	r.start()
	r.expect(r.result(id), "cancelled", "none", "none")
	r.waitFor("expired drop", func() bool { return r.metric("mctl_glovo_provider_commands_dropped_total", "reason", "expired") == 1 })
	r.settle()
	if r.writes() != 0 || r.f.Count("permit") != 0 || len(r.results(exp["command_id"].(string))) != 0 {
		t.Fatal("no permit, effect or result expected")
	}
	r.stop()

	for _, code := range []string{"command_cancelled", "command_expired", "lease_stale"} {
		r := newRig(t)
		r.f.FailNext("permit", bridgefake.Fault{Status: 409, Body: `{"error":"x","code":"` + code + `"}`})
		id := r.f.Enqueue(bridgefake.Command("place_order_fake"))
		r.start()
		r.waitFor("permit", func() bool { return r.f.Count("permit") == 1 })
		r.settle()
		if len(r.results(id)) != 0 || r.writes() != 0 {
			t.Fatalf("%s: stop with no result and no effect", code)
		}
	}
}

// T15: kill switch and open breaker.
func TestKillSwitchAndBreaker(t *testing.T) {
	r := newRig(t)
	r.disabled.Store(true)
	id := r.f.Enqueue(bridgefake.Command("place_order_fake"))
	r.start()
	r.expect(r.result(id), "failed_retryable", "none", "provider_unavailable")
	if r.f.Count("permit") != 0 || r.writes() != 0 {
		t.Fatal("no permit, no effect")
	}
	r.stop()

	r2 := newRig(t)
	r2.breaker.Record(true) // threshold 1: open
	id = r2.f.Enqueue(bridgefake.Command("place_order_fake"))
	r2.start()
	r2.expect(r2.result(id), "failed_retryable", "none", "provider_unavailable")
	if r2.f.Count("permit") != 0 {
		t.Fatal("no permit")
	}
}

// T16: the credential appears only in the Authorization header.
func TestCredentialCanary(t *testing.T) {
	r := newRig(t)
	r.f.FailNext("result", bridgefake.Fault{Status: 500})
	r.f.FailNext("permit", bridgefake.Fault{Status: 401, Body: `{"error":"x"}`})
	r.f.Enqueue(bridgefake.Command("place_order_fake"))
	r.f.Enqueue(bridgefake.Command("quote"))
	r.start()
	r.waitFor("traffic", func() bool { return r.f.Count("result") >= 2 })
	r.settle()
	var sawHeader bool
	for _, q := range r.f.Requests() {
		if q.Authorization == "Bearer "+canary {
			sawHeader = true
		}
		if len(leakcheck.Find(q.Body)) != 0 {
			t.Fatal("canary in a request body")
		}
	}
	if !sawHeader {
		t.Fatal("the fake never saw the credential")
	}
	if len(leakcheck.Find([]byte(r.logs.String()))) != 0 || strings.Contains(r.logs.String(), "lt_lease") {
		t.Fatalf("log leak: %s", r.logs.String())
	}
	var mb bytes.Buffer
	fams, _ := r.m.Registry.Gather()
	for _, f := range fams {
		_, _ = expfmt.MetricFamilyToText(&mb, f)
	}
	if len(leakcheck.Find(mb.Bytes())) != 0 || strings.Contains(mb.String(), "lt_lease") {
		t.Fatal("metric leak")
	}
	if _, err := (bridgeclient.FileCredential{Path: filepath.Join(t.TempDir(), "missing")}).Get(); err == nil || strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing file must name the setting only: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, []byte(" \n"), 0o600)
	if _, err := (bridgeclient.FileCredential{Path: empty}).Get(); err == nil || !strings.Contains(err.Error(), bridgeclient.CredentialSetting) {
		t.Fatalf("empty file: %v", err)
	}
}

// T22: 429 on each route.
func TestRateLimits(t *testing.T) {
	r := newRig(t)
	r.f.FailNext("claim", bridgefake.Fault{Status: 429, RetryAfter: "1"})
	r.start()
	r.waitFor("first claim", func() bool { return r.f.Count("claim") == 1 })
	start := time.Now()
	r.waitFor("second claim", func() bool { return r.f.Count("claim") >= 2 })
	if time.Since(start) < 900*time.Millisecond {
		t.Fatalf("claim retried after %s, want at least Retry-After", time.Since(start))
	}
	r.stop()

	r2 := newRig(t)
	r2.f.FailNext("result", bridgefake.Fault{Status: 429, RetryAfter: "1"})
	id := r2.f.Enqueue(bridgefake.Command("quote"))
	r2.start()
	r2.waitFor("two posts", func() bool { return len(r2.results(id)) == 2 })
	if !bytes.Equal(r2.f.ResultBodies()[0], r2.f.ResultBodies()[1]) {
		t.Fatal("identical bytes expected")
	}
	// Steady request rate at defaults stays under the 120/min budget:
	// claims at the default interval plus one permit and one result per command at 10/min.
	var c Config
	c.defaults()
	if perMin := float64(time.Minute)/float64(c.PollInterval) + 2*10; perMin >= 120 {
		t.Fatalf("steady rate %.0f/min", perMin)
	}
}

// T23: fail closed.
func TestFailClosed(t *testing.T) {
	r := newRig(t)
	r.f.FailNext("permit", bridgefake.Fault{Status: 418, Body: "<html>teapot"})
	id := r.f.Enqueue(bridgefake.Command("place_order_fake"))
	r.start()
	r.waitFor("unmapped metric", func() bool { return r.metric("mctl_glovo_provider_unmapped_responses_total", "route", "permit") == 1 })
	r.settle()
	if len(r.results(id)) != 0 || r.writes() != 0 {
		t.Fatal("unmapped permit answer: no effect, no result")
	}
	r.stop()

	r2 := newRig(t)
	r2.f.FailNext("result", bridgefake.Fault{Status: 401, Body: `{"error":"unauthorized"}`})
	r2.f.Enqueue(bridgefake.Command("quote"))
	r2.start()
	r2.waitFor("result post", func() bool { return r2.f.Count("result") == 1 })
	r2.settle()
	if r2.f.Count("result") != 1 {
		t.Fatal("a code-less 401 stops the command; no other body is sent")
	}
	r2.stop()

	r3 := newRig(t)
	r3.f.FailNext("result", bridgefake.Fault{Status: 418, Body: "???"})
	r3.f.Enqueue(bridgefake.Command("quote"))
	r3.start()
	r3.waitFor("unmapped result", func() bool { return r3.metric("mctl_glovo_provider_unmapped_responses_total", "route", "result") == 1 })
	r3.settle()
	if r3.f.Count("result") != 1 {
		t.Fatal("no resend on an unmapped answer")
	}
}

// T24 (poller half): a command without lease_token is dropped; a malformed claim is an error.
func TestMalformedClaimAndNoLeaseToken(t *testing.T) {
	r := newRig(t)
	d := bridgefake.Command("place_order_fake")
	r.f.ForceClaim(raw(d)) // no lease_token
	r.start()
	r.waitFor("drop", func() bool {
		return r.metric("mctl_glovo_provider_commands_dropped_total", "reason", "no_lease_token") == 1
	})
	r.settle()
	if r.f.Count("permit") != 0 || r.f.Count("result") != 0 || r.writes() != 0 {
		t.Fatal("not executed")
	}
	r.stop()

	r2 := newRig(t)
	r2.f.SetClaimBody([]byte(`{"schema_version":"bridge.mctl.ai/v1alpha1","commands":null}`))
	r2.start()
	r2.waitFor("claim errors", func() bool { return r2.metric("mctl_glovo_provider_claim_errors_total", "code", "malformed") >= 1 })
	if r2.p.Health.Ready() {
		t.Fatal("not ready without a good claim")
	}
}

// T25: deadlines.
func TestDeadlines(t *testing.T) {
	// A permit is never requested after the lease deadline.
	r := newRig(t, func(c *Config) { c.LeaseTTL = 100 * time.Millisecond; c.LeaseMargin = 99 * time.Millisecond })
	d := withLease(bridgefake.Command("place_order_fake"))
	r.p.Handle(context.Background(), time.Now().Add(-time.Second), v1alpha1.ClaimVersion, raw(d))
	if r.f.Count("permit") != 0 || r.writes() != 0 {
		t.Fatal("no permit after the lease deadline")
	}
	if r.metric("mctl_glovo_provider_commands_dropped_total", "reason", "lease_deadline") != 1 {
		t.Fatal("lease_deadline drop expected")
	}
}

func TestResultRetryContinuesPastLeaseDeadline(t *testing.T) {
	r := newRig(t, func(c *Config) { c.LeaseTTL = 6 * time.Second; c.LeaseMargin = 5700 * time.Millisecond })
	r.f.SetLeaseTTL(300 * time.Millisecond)
	for i := 0; i < 8; i++ {
		r.f.FailNext("result", bridgefake.Fault{Status: 503, AfterStore: i == 0})
	}
	id := r.f.Enqueue(bridgefake.Command("quote"))
	r.start()
	r.waitFor("a replay after lease expiry", func() bool { return r.metric("mctl_glovo_provider_results_total", "status", "replayed") == 1 })
	if st, _, _ := r.f.State(id); st != bridgefake.StatusCompleted {
		t.Fatal("completed")
	}
}

// T26 and T27: v1alpha2.
func TestV2PlaceOrder(t *testing.T) {
	r := newRig(t)
	r.f.SetClaimVersion(v1alpha1.ClaimV2)
	id := r.f.Enqueue(bridgefake.PlaceOrderV2())
	r.start()
	res := r.result(id)
	r.expect(res, "succeeded", "applied", "none")
	if res.SchemaVersion != v1alpha1.Version || r.f.Count("permit") != 1 || r.writes() != 1 {
		t.Fatalf("v1alpha1 result, one permit, one effect expected: %+v", res)
	}
	if e, ok := r.store.EffectOf(id); !ok || len(e.Lines) != 1 || e.Lines[0].ItemID != "FAKE-1" {
		t.Fatalf("effect = %+v", e)
	}
}

func TestV2RefusedLocally(t *testing.T) {
	v2 := func(f func(map[string]any)) map[string]any { d := withLease(bridgefake.PlaceOrderV2()); f(d); return d }
	cases := map[string]map[string]any{
		"v2 cancel":       v2(func(d map[string]any) { d["kind"] = "cancel_order_fake" }),
		"v2 read":         v2(func(d map[string]any) { d["kind"] = "read_status" }),
		"v2 missing":      v2(func(d map[string]any) { delete(d, "approval_ref") }),
		"v2 extra":        v2(func(d map[string]any) { d["extra"] = 1 }),
		"unknown version": v2(func(d map[string]any) { d["schema_version"] = "bridge.mctl.ai/v1alpha3" }),
		"v1 basket": func() map[string]any {
			d := withLease(bridgefake.PlaceOrderV2())
			d["schema_version"] = v1alpha1.Version
			return d
		}(),
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.f.SetClaimVersion(v1alpha1.ClaimV2)
			r.f.ForceClaim(raw(d))
			r.start()
			r.waitFor("local refusal", func() bool { return r.f.Count("result") == 1 })
			r.settle()
			var body v1alpha1.Result
			_ = json.Unmarshal(r.f.ResultBodies()[0], &body)
			if body.Outcome != "failed_terminal" || body.ProviderEffect != "none" || r.f.Count("permit") != 0 || r.writes() != 0 {
				t.Fatalf("body=%+v permits=%d writes=%d", body, r.f.Count("permit"), r.writes())
			}
		})
	}
	// A v2 command inside a v1alpha1 envelope is refused too.
	r := newRig(t)
	r.f.ForceClaim(raw(withLease(bridgefake.PlaceOrderV2())))
	r.start()
	r.waitFor("refusal", func() bool { return r.f.Count("result") == 1 })
	r.settle()
	if r.f.Count("permit") != 0 || r.writes() != 0 {
		t.Fatal("v2 in a v1 envelope must not run")
	}
}

func TestUnknownClaimVersionIsFailedClaim(t *testing.T) {
	r := newRig(t)
	r.f.SetClaimBody([]byte(`{"schema_version":"bridge.mctl.ai/claim/v1alpha3","commands":[` + string(raw(withLease(bridgefake.Command("place_order_fake")))) + `]}`))
	r.start()
	r.waitFor("claim error", func() bool { return r.metric("mctl_glovo_provider_claim_errors_total", "code", "malformed") >= 1 })
	r.settle()
	if r.f.Count("permit") != 0 || r.f.Count("result") != 0 || r.writes() != 0 {
		t.Fatal("nothing from a failed claim may run")
	}
}

func TestGracefulStop(t *testing.T) {
	r := newRig(t)
	r.start()
	r.waitFor("claims", func() bool { return r.f.Count("claim") >= 2 })
	r.stop()
	if !r.p.Health.Ready() {
		// a stopped poller keeps its last readiness until the window ends; only shutdown flips it
		t.Log("not ready after stop")
	}
}
