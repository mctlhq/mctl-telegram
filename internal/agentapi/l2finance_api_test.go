//go:build l2finance

package agentapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// l2Action is the persisted view of one agent_actions row.
type l2Action struct {
	ID, JobID, ConvID, InstallRev int64
	Type, Intent, Status          string
	Decision, Reasons             string
}

func (h *l2APIHarness) actions(uid int64) []l2Action {
	h.t.Helper()
	rows, err := h.store.DB.Query(`SELECT id, COALESCE(job_id,0), COALESCE(conversation_id,0), COALESCE(install_revision,0),
		action_type, intent, status, policy_decision, policy_reasons FROM agent_actions WHERE user_id = $1 ORDER BY id`, uid)
	if err != nil {
		h.t.Fatalf("query actions: %v", err)
	}
	defer rows.Close()
	var out []l2Action
	for rows.Next() {
		var a l2Action
		if err := rows.Scan(&a.ID, &a.JobID, &a.ConvID, &a.InstallRev, &a.Type, &a.Intent, &a.Status, &a.Decision, &a.Reasons); err != nil {
			h.t.Fatalf("scan action: %v", err)
		}
		out = append(out, a)
	}
	return out
}

func (h *l2APIHarness) summaryBody(conv int64, text string) ownerNotifyRequest {
	return ownerNotifyRequest{ConversationID: conv, Intent: "lead", Text: text}
}

func (h *l2APIHarness) bump() {
	h.t.Helper()
	if err := h.store.UpdateAgentProfileFields(context.Background(), h.alice, db.AgentProfileUpdate{BumpInstallRevision: true}); err != nil {
		h.t.Fatalf("bump revision: %v", err)
	}
}

func TestL2Finance_T2(t *testing.T) {
	h := l2NewAPIHarness(t, db.AgentModeObserve, "")
	rec := h.do(h.jobID, "POST", "/notify/summary", ownerNotifyRequest{Intent: "lead", Text: l2Finance})
	acts := h.actions(h.alice)
	// Count all owner notifications before examining the unique row:
	// QueryRow alone would silently miss duplicates or another tenant's row.
	notifCount := h.count(`SELECT COUNT(*) FROM owner_notifications`)
	var notifUser int64
	var kind string
	if notifCount == 1 {
		if err := h.store.DB.QueryRow(`SELECT user_id, kind FROM owner_notifications`).Scan(&notifUser, &kind); err != nil {
			t.Fatalf("read sole owner notification: %v", err)
		}
	}
	carolA, carolN := h.rowsFor(h.carol)
	ok := rec.Code == http.StatusOK && len(acts) == 1 && acts[0].Status == db.ActionExecuted &&
		notifCount == 1 && notifUser == h.alice && kind == db.NotificationSummary && carolA+carolN == 0 && h.peer.count() == 0
	if !ok {
		t.Fatalf("ordinary owner routing changed: %s; review T2 rubric", rec.Body.String())
	}
	l2Record(t, "T2.ordinary_owner_routing", l2Pass, fmt.Sprintf(
		"http=%d actions=%d status=%v notif_rows=%d notif_owner_is_alice=%t kind=%s carol_rows=%d peer_sink=%d",
		rec.Code, len(acts), statuses(acts), notifCount, notifUser == h.alice, kind, carolA+carolN, h.peer.count()))
	// #1244 T2 explicitly grades the Bob-conversation owner-summary bypass
	// as FAIL/GAP against finance owner invocation, even though ordinary
	// owner routing itself is correct. Never reclassify it as a PASS.
	expectGap(t, "T2.bob_job_owner_summary", ok,
		"finance-looking text from Bob-conversation job allowed to queue owner summary without a finance owner-invocation grant")
	l2Record(t, "T2.finance_origin_authorization", l2NotImplemented,
		"no finance-source label, source consent or finance policy gate exists; finance-looking text treated as ordinary text; no PASS or FAIL inferred")
}

func statuses(a []l2Action) []string {
	var s []string
	for _, x := range a {
		s = append(s, x.Status+"/"+x.Decision)
	}
	return s
}

func TestL2Finance_T3(t *testing.T) {
	t.Run("account_foreign_conversation", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeObserve, "")
		r1 := h.do(h.account, "POST", "/notify/summary", h.summaryBody(h.convC.ID, l2Finance))
		r2 := h.do(h.account, "POST", "/actions/propose_reply", proposeReplyRequest{ConversationID: h.convC.ID, Intent: "lead", Text: l2Finance})
		okc := func(c int) bool { return c == http.StatusForbidden || c == http.StatusNotFound }
		ok := okc(r1.Code) && okc(r2.Code) && h.noRows()
		l2Record(t, "T3.account_foreign_conversation", l2Outcome(ok), fmt.Sprintf("notify=%d propose=%d rows_none=%t", r1.Code, r2.Code, h.noRows()))
		if !ok {
			t.Errorf("foreign conversation not isolated")
		}
	})
	t.Run("account_foreign_context", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeObserve, "")
		rec := h.do(h.account, "GET", "/conversations/"+strconv.FormatInt(h.convC.ID, 10)+"/context", nil)
		ok := rec.Code == http.StatusForbidden || rec.Code == http.StatusNotFound
		l2Record(t, "T3.account_foreign_context", l2Outcome(ok), fmt.Sprintf("http=%d", rec.Code))
		if !ok {
			t.Errorf("foreign context readable: %d", rec.Code)
		}
	})
	t.Run("job_foreign_conversation", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeObserve, "")
		r1 := h.do(h.jobID, "POST", "/notify/summary", h.summaryBody(h.convC.ID, l2Finance))
		r2 := h.do(h.jobID, "POST", "/actions/propose_reply", proposeReplyRequest{ConversationID: h.convC.ID, Intent: "lead", Text: l2Finance})
		r3 := h.do(h.jobID, "GET", "/conversations/"+strconv.FormatInt(h.convC.ID, 10)+"/context", nil)
		denied := h.count(`SELECT COUNT(*) FROM audit_logs WHERE user_id = $1 AND status = 'denied'`, h.alice)
		ok := r1.Code == 403 && r2.Code == 403 && r3.Code == 403 && denied >= 2 && h.noRows()
		l2Record(t, "T3.job_foreign_conversation", l2Outcome(ok), fmt.Sprintf(
			"notify=%d propose=%d context=%d alice_denied_audits=%d rows_none=%t", r1.Code, r2.Code, r3.Code, denied, h.noRows()))
		if !ok {
			t.Errorf("job binding did not isolate")
		}
	})
	t.Run("account_foreign_job", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeObserve, "")
		// The harness's own claimed jobs hold no action rows; none may appear.
		rec := h.do(h.account, "POST", "/notify/summary", ownerNotifyRequest{JobID: h.jobC.ID, Attempt: h.jobC.Attempts, Intent: "lead", Text: l2Finance})
		ok := rec.Code >= 400 && rec.Code < 500 && h.noRows()
		l2Record(t, "T3.account_foreign_job", l2Outcome(ok), fmt.Sprintf("http=%d rows_none=%t", rec.Code, h.noRows()))
		if !ok {
			t.Errorf("foreign job accepted: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("finance_source_consent", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeObserve, "")
		rec := h.do(h.account, "POST", "/notify/summary", map[string]any{"text": l2Finance, "finance_source": "bank"})
		if rec.Code != http.StatusBadRequest || !h.noRows() {
			t.Fatalf("unexpected: %d rows_none=%t", rec.Code, h.noRows())
		}
		l2Record(t, "T3.finance_source_consent", l2NotImplemented,
			fmt.Sprintf("http=%d decodeStrict rejects unknown field; no consent/source concept; no store mocked", rec.Code))
	})
}

func l2Outcome(ok bool) string {
	if ok {
		return l2Pass
	}
	return l2FailGap
}

func TestL2Finance_T73(t *testing.T) {
	t.Run("with_job_id", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeGuarded, "")
		h.bump()
		rec := h.do(h.jobID, "POST", "/notify/summary", ownerNotifyRequest{JobID: h.jobA.ID, Attempt: h.jobA.Attempts, Intent: "lead", Text: l2Finance})
		var resp actionResponse
		decodeBody(t, rec, &resp)
		ok := rec.Code == 200 && resp.Decision == string(policy.Deny) && len(resp.Reasons) == 1 && resp.Reasons[0] == policy.ReasonInstallChanged
		_, n := h.rowsFor(h.alice)
		l2Record(t, "T7.3.with_job_id", l2Outcome(ok && n == 0), fmt.Sprintf("http=%d decision=%s reasons=%q notif_rows=%d", rec.Code, resp.Decision, resp.Reasons, n))
		if !ok || n != 0 {
			t.Errorf("control failed: %+v", resp)
		}
	})
	t.Run("omit_job_id", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeGuarded, "")
		h.bump()
		rec := h.do(h.jobID, "POST", "/notify/summary", ownerNotifyRequest{Intent: "lead", Text: l2Finance})
		var raw map[string]any
		decodeBody(t, rec, &raw)
		acts := h.actions(h.alice)
		_, n := h.rowsFor(h.alice)
		observed := rec.Code == 200 && len(acts) == 1 && acts[0].Status == db.ActionExecuted && n == 1
		ev := fmt.Sprintf("http=%d actions=%d notif_rows=%d", rec.Code, len(acts), n)
		if len(acts) == 1 {
			ev += fmt.Sprintf(" status=%s decision=%s persisted_job_id=%d persisted_install_revision=%d claimed_job_id=%d", acts[0].Status, acts[0].Decision, acts[0].JobID, acts[0].InstallRev, h.jobA.ID)
		}
		expectGap(t, "T7.3.omit_job_id", observed, ev)
	})
}

func TestL2Finance_T9(t *testing.T) {
	t.Run("observe_no_peer_send", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeObserve, "")
		rec := h.do(h.jobID, "POST", "/actions/propose_reply", proposeReplyRequest{Intent: "discovery", Text: l2Finance})
		var resp actionResponse
		decodeBody(t, rec, &resp)
		acts := h.actions(h.alice)
		ok := rec.Code == 200 && len(acts) == 1 && acts[0].Status != db.ActionApproved && acts[0].Status != db.ActionExecuted && h.peer.count() == 0
		l2Record(t, "T9.observe_no_peer_send", l2Outcome(ok), fmt.Sprintf(
			"http=%d decision=%s status=%s persisted=%v api_peer_sink=%d (API has no sender; not an executor claim)", rec.Code, resp.Decision, resp.Status, statuses(acts), h.peer.count()))
		if !ok {
			t.Errorf("observe mode result: %+v", resp)
		}
	})
	t.Run("guarded_allowlisted", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeGuarded, "discovery")
		rec := h.do(h.jobID, "POST", "/actions/propose_reply", proposeReplyRequest{Intent: "discovery", Text: l2Finance})
		var resp actionResponse
		decodeBody(t, rec, &resp)
		acts := h.actions(h.alice)
		ok := rec.Code == 200 && len(acts) == 1 && h.peer.count() == 0 && acts[0].Decision != "" && acts[0].Status != db.ActionExecuted
		l2Record(t, "T9.guarded_allowlisted", l2Outcome(ok), fmt.Sprintf(
			"http=%d decision=%s status=%s persisted=%v api_peer_sink=%d; approved is an API policy state, not evidence of delivery", rec.Code, resp.Decision, resp.Status, statuses(acts), h.peer.count()))
		if !ok {
			t.Errorf("guarded result: %+v", resp)
		}
	})
	t.Run("executor_peer_send", func(t *testing.T) {
		l2Record(t, "T9.executor_peer_send", l2CannotObserve,
			"delivery after an approved action happens in the executor outside this slice; an inert sink on an API without a sender proves nothing")
	})
	t.Run("finance_tier", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeGuarded, "discovery")
		rec := h.do(h.jobID, "POST", "/actions/propose_reply", map[string]any{"intent": "discovery", "text": l2Finance, "tier": "finance"})
		if rec.Code != http.StatusBadRequest || !h.noRows() {
			t.Fatalf("unexpected: %d rows_none=%t", rec.Code, h.noRows())
		}
		l2Record(t, "T9.finance_tier", l2NotImplemented, fmt.Sprintf("http=%d unknown field tier rejected; no finance tier exists", rec.Code))
	})
}

// l2Sources dumps every plaintext column the spec names, one string per source.
func (h *l2APIHarness) sources() map[string]string {
	h.t.Helper()
	dump := func(q string, n int) string {
		rows, err := h.store.DB.Query(q)
		if err != nil {
			h.t.Fatalf("dump %q: %v", q, err)
		}
		defer rows.Close()
		var sb strings.Builder
		for rows.Next() {
			vals := make([]any, n)
			ptrs := make([]any, n)
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				h.t.Fatalf("scan: %v", err)
			}
			for _, v := range vals {
				switch x := v.(type) {
				case []byte:
					sb.Write(x)
				default:
					fmt.Fprint(&sb, x)
				}
				sb.WriteByte('|')
			}
			sb.WriteByte('\n')
		}
		return sb.String()
	}
	return map[string]string{
		"audit_logs":                 dump(`SELECT tool_name, COALESCE(peer_redacted,''), status, COALESCE(error,'') FROM audit_logs`, 4),
		"agent_actions":              dump(`SELECT intent, policy_reasons, payload_encrypted FROM agent_actions`, 3),
		"owner_notifications.stored": dump(`SELECT kind, status, body_encrypted FROM owner_notifications`, 3),
	}
}

func (h *l2APIHarness) scenario() {
	h.do(h.jobID, "POST", "/notify/summary", ownerNotifyRequest{Intent: "lead", Text: l2Finance})
	h.do(h.jobID, "POST", "/actions/propose_reply", proposeReplyRequest{Intent: "discovery", Text: l2Finance})
	h.do(h.account, "POST", "/notify/summary", h.summaryBody(h.convC.ID, l2Finance))
	h.bump()
	h.do(h.jobID, "POST", "/notify/summary", ownerNotifyRequest{JobID: h.jobA.ID, Attempt: h.jobA.Attempts, Intent: "lead", Text: l2Finance})
}

func TestL2Finance_T10(t *testing.T) {
	t.Run("action_rows", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeGuarded, "discovery")
		h.scenario()
		acts := h.actions(h.alice)
		bad := 0
		denied := 0
		for _, a := range acts {
			if a.Status == "" || a.Decision == "" {
				bad++
			}
			if a.Status == db.ActionDenied {
				denied++
				if a.Reasons == "" {
					bad++
				}
			}
		}
		l2Record(t, "T10.action_rows", l2Outcome(bad == 0 && len(acts) > 0), fmt.Sprintf("rows=%d denied=%d malformed=%d", len(acts), denied, bad))
		if bad != 0 {
			t.Errorf("malformed action rows")
		}
	})
	t.Run("denycode_persisted", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeGuarded, "discovery")
		h.scenario()
		code := string(policy.DenyInstallChanged)
		metric := h.denialMetric(code)
		durable := false
		for _, src := range []string{"audit_logs", "agent_actions"} {
			if strings.Contains(h.sources()[src], code) {
				durable = true
			}
		}
		var denyCols int
		rows, err := h.store.DB.Query(`SELECT name FROM pragma_table_info('agent_actions') WHERE name LIKE '%deny%' OR name LIKE '%code%'`)
		if err == nil {
			for rows.Next() {
				var n string
				_ = rows.Scan(&n)
				if n != "approval_code" && !strings.HasPrefix(n, "approval_code_") {
					denyCols++
				}
			}
			rows.Close()
		}
		ev := fmt.Sprintf("code=%s metric_count=%v durable_in_audit_or_actions=%t deny_code_columns=%d", code, metric, durable, denyCols)
		expectGap(t, "T10.denycode_persisted", metric >= 1 && !durable && denyCols == 0, ev)
	})
	t.Run("redaction_text", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeGuarded, "discovery")
		var buf bytes.Buffer
		l2CaptureSlog(t, audit.NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))
		h.scenario()
		src := h.sources()
		err := l2AssertNoMarker(src)
		l2Record(t, "T10.redaction_text", l2Outcome(err == nil), fmt.Sprintf("durable_sources_only err=%v", err))
		if err != nil {
			t.Errorf("leak: %v", err)
		}
		// Observable slog redaction: the scenario may emit nothing, so a
		// synthetic marker is sent through the production redacting handler.
		// Zero bytes is never a PASS.
		slog.Info("l2 t10 slog", "text", l2Marker)
		slogBytes := buf.Len()
		slogErr := l2AssertNoMarker(map[string]string{"slog": buf.String()})
		switch {
		case slogBytes == 0:
			l2Record(t, "T10.redaction_slog", l2CannotObserve, "slog_bytes=0: no log event reached the redacting handler")
		case slogErr != nil:
			l2Record(t, "T10.redaction_slog", l2FailGap, fmt.Sprintf("slog_bytes=%d err=%v", slogBytes, slogErr))
			t.Errorf("slog leak: %v", slogErr)
		default:
			l2Record(t, "T10.redaction_slog", l2Pass, fmt.Sprintf("slog_bytes=%d marker redacted", slogBytes))
		}
	})
	t.Run("intent_channel", func(t *testing.T) {
		h := l2NewAPIHarness(t, db.AgentModeGuarded, "discovery")
		var buf bytes.Buffer
		l2CaptureSlog(t, audit.NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))
		h.do(h.jobID, "POST", "/notify/summary", ownerNotifyRequest{Intent: l2Marker, Text: "synthetic text"})
		h.do(h.jobID, "POST", "/actions/propose_reply", proposeReplyRequest{Intent: l2Marker, Text: "synthetic text"})
		src := h.sources()
		src["slog"] = buf.String()
		err := l2AssertNoMarker(src)
		// A persisted plaintext intent is an expected, reviewed FAIL/GAP in
		// this test-only slice. Fail the test on drift until the rubric is
		// independently updated; a different leak source is not equivalent.
		observed := strings.Contains(src["agent_actions"], l2Marker)
		expectGap(t, "T10.intent_channel", observed, fmt.Sprintf(
			"plaintext_intent_in_agent_actions=%t marker_check=%v", observed, err))
		// Only the reviewed agent_actions.intent leak is expected. A new leak
		// in any other durable source or in slog must fail the binary, even
		// while the known intent gap continues to reproduce.
		delete(src, "agent_actions")
		if extraErr := l2AssertNoMarker(src); extraErr != nil {
			t.Errorf("T10.intent_channel: unexpected additional leak: %v", extraErr)
		}
	})
	t.Run("traces", func(t *testing.T) {
		spans := 0
		files, _ := filepath.Glob("*.go")
		instrumented := 0
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, _ := os.ReadFile(f)
			if strings.Contains(string(b), "go.opentelemetry.io") {
				instrumented++
			}
		}
		l2Record(t, "T10.traces", l2CannotObserve, fmt.Sprintf(
			"spans=%d agentapi_files_importing_otel=%d no exercised instrumentation, empty provider is not a PASS", spans, instrumented))
	})
}

// denialMetric returns the AgentPolicyDenialsTotal sample sum for a code.
func (h *l2APIHarness) denialMetric(code string) float64 {
	h.t.Helper()
	mfs, err := h.reg.Prometheus.Gather()
	if err != nil {
		h.t.Fatalf("gather: %v", err)
	}
	var sum float64
	for _, mf := range mfs {
		if mf.GetName() != "mctl_agent_policy_denials_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "reason" && l.GetValue() == code {
					sum += m.GetCounter().GetValue()
				}
			}
		}
	}
	return sum
}

func TestL2Finance_M4(t *testing.T) {
	var raw bytes.Buffer
	l2CaptureSlog(t, slog.NewJSONHandler(&raw, nil))
	slog.Info("l2 m4", "text", l2Marker)
	if err := l2AssertNoMarker(map[string]string{"slog_unredacted": raw.String()}); err == nil {
		t.Fatal("M4: l2AssertNoMarker did not detect an unredacted marker")
	}
	l2Record(t, "M4", l2Pass, "detected: unredacted JSON handler leak reported by the same helper used by T10")

	var red bytes.Buffer
	l2CaptureSlog(t, audit.NewRedactingHandler(slog.NewJSONHandler(&red, nil)))
	slog.Info("l2 m4", "text", l2Marker)
	if err := l2AssertNoMarker(map[string]string{"slog_redacted": red.String()}); err != nil {
		t.Fatalf("M4.redacted_twin: %v", err)
	}
	l2Record(t, "M4.redacted_twin", l2Pass, "production redacting handler returns nil from the same helper")
}

func TestL2Finance_Offline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://192.0.2.1:443/", nil)
	_, dialErr := http.DefaultClient.Do(req)
	_, lookupErr := net.LookupHost("example.invalid")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	resp, loopErr := http.Get(srv.URL)
	if loopErr == nil {
		resp.Body.Close()
	}
	ok := errors.Is(dialErr, errL2ExternalDial) && errors.Is(lookupErr, errL2ExternalDial) && loopErr == nil
	if !ok && dialErr != nil && strings.Contains(dialErr.Error(), errL2ExternalDial.Error()) &&
		lookupErr != nil && strings.Contains(lookupErr.Error(), errL2ExternalDial.Error()) && loopErr == nil {
		ok = true
	}
	l2Record(t, "OFFLINE.default_paths", l2Outcome(ok), fmt.Sprintf("dial_refused=%t lookup_refused=%t loopback_ok=%t",
		dialErr != nil, lookupErr != nil, loopErr == nil))
	if !ok {
		t.Errorf("dial=%v lookup=%v loop=%v", dialErr, lookupErr, loopErr)
	}
	l2Record(t, "OFFLINE.whole_process", l2CannotObserve, "guards cover net.DefaultResolver and http.DefaultTransport only; not a whole-process egress firewall")
}
