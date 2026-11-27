package pa_test

// Acceptance tests of the write executor (#1320 slice P2-S3,
// connector.WriteExecutor.DispatchApproved) against the real approval
// ledger, connection manager, outbox and ADR 0003 audit chain, on SQLite
// and, with TEST_DATABASE_URL, on Postgres. The MCP server is a fake
// behind connector.WriteEndpoint; the byte-exact egress itself is tested
// in internal/pa/connector (TestS2D7_CallToolExactSendsTheBytes).
//
// Threat model rows: S2-A3 (T7), S2-F3 (T11), S2-C11, S2-C13 and the
// executor halves of S2-A1, S2-C10 and S2-C12 (T2), S2-D7 (T5).

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

var writeMasterKey = []byte("fedcba9876543210fedcba9876543210")

const writeTool = "send_message"

// writeArgs are canonical arguments with the characters encoding/json
// rewrites inside a RawMessage ('<', '>' and '&' become escapes there):
// marshalling them again would send other bytes.
const writeArgs = `{"text":"<b>1 & 2</b>","to":"Carol"}`

func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeEP is a fake server behind connector.WriteEndpoint. It records the
// argument bytes of every tools/call exactly as it was handed them.
type writeEP struct {
	mu      sync.Mutex
	calls   [][]byte
	bearers []string
	onCall  func()
	err     error
	out     []byte
	// block makes the call wait for its context.
	block bool
}

func (f *writeEP) Server() string { return "tg" }

func (f *writeEP) CallToolExact(ctx context.Context, tok connection.Secret, tool string, args []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, slices.Clone(args))
	f.bearers = append(f.bearers, tok.Reveal())
	hook, err, out, block := f.onCall, f.err, f.out, f.block
	f.mu.Unlock()
	if tool != writeTool {
		return nil, errors.New("fake: unexpected tool " + tool)
	}
	if hook != nil {
		hook()
	}
	if block {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, errors.New("fake: not cancelled")
		}
	}
	if err != nil {
		return nil, err
	}
	if out != nil {
		return out, nil
	}
	return []byte(`{"content":[{"type":"text","text":"sent"}]}`), nil
}

func (f *writeEP) sent() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// fakeFresh answers the dispatch-time tools/list with a definition that
// matches what newWriteEnv's approvals bind, unless a test changes it.
type fakeFresh struct {
	mu    sync.Mutex
	tool  connector.FreshTool
	err   error
	hook  func()
	calls int
}

func (f *fakeFresh) FreshTool(_ context.Context, req connector.FreshRequest) (connector.FreshTool, error) {
	f.mu.Lock()
	f.calls++
	tool, err, hook := f.tool, f.err, f.hook
	f.mu.Unlock()
	if req.Token.Reveal() == "" || req.Tool != writeTool || req.Server != "tg" {
		return connector.FreshTool{}, errors.New("fake: unexpected fresh request")
	}
	if hook != nil {
		hook()
	}
	return tool, err
}

func (f *fakeFresh) asked() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type writeEnv struct {
	*dispatchEnv
	ep     *writeEP
	fresh  *fakeFresh
	sealer *approval.Sealer
	x      *connector.WriteExecutor
	conv   string
	job    int64
	denied atomic.Bool
}

// newWriteEnv is a dispatch env where Alice has consented, has an open
// conversation and PA_WRITES_ENABLED reads true. mutate adjusts the
// executor's configuration.
func newWriteEnv(t *testing.T, s *db.Store, mutate func(*connector.WriteConfig)) *writeEnv {
	t.Helper()
	e := &writeEnv{dispatchEnv: newDispatchEnv(t, s), ep: &writeEP{}}
	e.h.Consent(alice)
	e.h.ConsentActions(alice)
	e.h.Text(alice, "please send it")
	if err := s.DB.QueryRow(`SELECT id FROM pa_conversations WHERE principal = $1 AND closed_at_ms = 0`, alice).Scan(&e.conv); err != nil {
		t.Fatalf("conversation: %v", err)
	}
	if err := s.DB.QueryRow(`SELECT id FROM pa_jobs WHERE principal = $1 ORDER BY id DESC LIMIT 1`, alice).Scan(&e.job); err != nil {
		t.Fatalf("job: %v", err)
	}
	e.flags.Store(&connector.Flags{ExternalTools: true, Writes: true, Servers: map[string]bool{"tg": true}})
	e.fresh = &fakeFresh{tool: connector.FreshTool{
		SchemaSHA: shaHex([]byte("schema")), DescriptionSHA: shaHex([]byte("description")),
		AnnotationSHA: shaHex([]byte("annotations")), Tier: catalog.TierApprove, Class: catalog.ClassWrite,
	}}
	var err error
	if e.sealer, err = approval.NewSealer(writeMasterKey); err != nil {
		t.Fatal(err)
	}
	cfg := connector.WriteConfig{
		Store: s, Connections: e.mgr,
		Endpoints: map[string]connector.WriteEndpoint{"tg": e.ep},
		Executor:  &connector.Executor{Sink: e.sink, Now: e.h.Now},
		Sealer:    e.sealer,
		Flags: func() (connector.Flags, error) {
			if e.flagErr.Load() {
				return connector.Flags{}, errors.New("injected flag error")
			}
			return *e.flags.Load(), nil
		},
		Allowed: func(int64) bool { return !e.denied.Load() },
		Fresh:   e.fresh,
		Scopes:  testWriteScopes(t),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	if e.x, err = connector.NewWriteExecutor(cfg); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *writeEnv) inTx(fn func(tx *sql.Tx) error) {
	e.t.Helper()
	tx, err := e.store.DB.BeginTx(context.Background(), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		e.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		e.t.Fatal(err)
	}
}

func (e *writeEnv) binding(argsSHA string) approval.Binding {
	return approval.Binding{
		Principal: alice, ConnectionID: e.connA.ID, AuthorityRevision: e.connA.AuthorityRevision,
		Server: "tg", Tool: writeTool, Class: catalog.ClassWrite,
		SchemaSHA: shaHex([]byte("schema")), DescriptionSHA: shaHex([]byte("description")),
		AnnotationSHA: shaHex([]byte("annotations")), ArgsSHA: argsSHA, ConversationID: e.conv, JobID: e.job,
	}
}

// save stores a and approves it, as the card's Approve tap will.
func (e *writeEnv) save(a approval.Approval) approval.Approval {
	e.t.Helper()
	ctx := context.Background()
	e.inTx(func(tx *sql.Tx) error {
		if err := e.store.CreatePAApproval(ctx, tx, a); err != nil {
			return err
		}
		_, err := e.store.ApprovePAApproval(ctx, tx, alice, a.ID, e.h.Now())
		return err
	})
	return a
}

// approved is an approved approval of args, sealed by the real sealer.
func (e *writeEnv) approved(args string) approval.Approval {
	e.t.Helper()
	canon, err := catalog.CanonicalArgs([]byte(args))
	if err != nil {
		e.t.Fatal(err)
	}
	a, err := approval.New(e.binding(shaHex(canon)), e.h.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	if a, err = e.sealer.Seal(a, canon); err != nil {
		e.t.Fatal(err)
	}
	return e.save(a)
}

// forgeSeal seals plain for approval id under the bound hash argsSHA,
// whatever plain hashes to: the blob a writer of the row with the service
// key could leave. It repeats approval.Sealer.Seal without its checks.
func forgeSeal(t *testing.T, principal int64, id, argsSHA string, plain []byte) []byte {
	t.Helper()
	key, err := crypto.DeriveSubkey(writeMasterKey, principal, approval.KeyInfo)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	const label = "mctl-pa-approval-args/v1"
	aad := append([]byte(label), binary.BigEndian.AppendUint64(nil, uint64(principal))...)
	for _, part := range []string{id, argsSHA} {
		aad = binary.BigEndian.AppendUint32(aad, uint32(len(part)))
		aad = append(aad, part...)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(append([]byte{0x01}, nonce...), nonce, plain, aad)
}

func (e *writeEnv) dispatch(id string) connector.WriteOutcome {
	e.t.Helper()
	out, err := e.x.DispatchApproved(context.Background(), alice, id)
	if err != nil {
		e.t.Fatalf("dispatch: %v", err)
	}
	return out
}

func (e *writeEnv) strings(q string, args ...any) []string {
	e.t.Helper()
	rows, err := e.store.DB.Query(q, args...)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *writeEnv) dispatches() []string {
	return e.strings(`SELECT status FROM pa_dispatches WHERE principal = $1 ORDER BY created_at_ms, id`, alice)
}

func (e *writeEnv) notices() []string {
	return e.strings(`SELECT kind FROM pa_outbox WHERE principal = $1 AND approval_id <> '' ORDER BY id`, alice)
}

// approvalState is the row's status and whether its arguments are erased.
func (e *writeEnv) approvalState(id string) string {
	e.t.Helper()
	var st string
	var erased bool
	if err := e.store.DB.QueryRow(`SELECT status, sealed_args IS NULL FROM pa_approvals WHERE principal = $1 AND id = $2`,
		alice, id).Scan(&st, &erased); err != nil {
		e.t.Fatal(err)
	}
	if erased {
		st += "/erased"
	}
	return st
}

// writeAudit is the statuses of Alice's audit rows for the write tool,
// oldest first, and the rows themselves.
func (e *writeEnv) writeAudit() ([]string, []auditRow) {
	e.t.Helper()
	var st []string
	var rows []auditRow
	for _, r := range e.audit(alice) {
		if r.tool == "pa:tg/"+writeTool {
			st = append(st, r.status)
			rows = append(rows, r)
		}
	}
	return st, rows
}

func field(record, key string) string {
	for _, f := range strings.Fields(record) {
		if v, ok := strings.CutPrefix(f, key+"="); ok {
			return v
		}
	}
	return ""
}

// wantNotSent asserts a refusal that sent nothing and ended the approval:
// no tools/call, no dispatch record, the approval refused with its
// arguments erased, the "not carried out" notice, and reason in the audit.
func (e *writeEnv) wantNotSent(out connector.WriteOutcome, a approval.Approval, reason string) {
	e.t.Helper()
	if out.Status != connector.StatusRefused || out.Reason != reason || out.Output != nil || out.DispatchID != "" {
		e.t.Fatalf("outcome %+v, want refused %s", out, reason)
	}
	if n := len(e.ep.sent()); n != 0 {
		e.t.Fatalf("%d tools/call sent for a refused dispatch", n)
	}
	if d := e.dispatches(); len(d) != 0 {
		e.t.Fatalf("dispatch records %v for a refused dispatch", d)
	}
	if st := e.approvalState(a.ID); st != "refused/erased" {
		e.t.Fatalf("approval %s, want refused/erased", st)
	}
	if n := e.notices(); !slices.Equal(n, []string{"write_not_sent"}) {
		e.t.Fatalf("notices %v", n)
	}
	st, rows := e.writeAudit()
	if len(rows) == 0 || st[len(st)-1] != "refused" || field(rows[len(rows)-1].peer, "reason") != reason {
		e.t.Fatalf("audit %v %+v, want a final refused reason=%s", st, rows, reason)
	}
}

// TestWriteDispatch_HappyPath: an approved call is sent once, with the
// connection's token opened server-side, and every record of it agrees:
// dispatch ok, approval done with its arguments erased, one notice, and a
// pre-dispatch and a result audit entry under one call id (S1-U2) carrying
// the approval, the approver, the tier, the class and the taint (T12).
func TestWriteDispatch_HappyPath(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newWriteEnv(t, s, nil)
		a := e.approved(writeArgs)
		out := e.dispatch(a.ID)
		if out.Status != connector.StatusOK || out.Reason != "" || !strings.Contains(string(out.Output), "sent") || out.DispatchID == "" {
			t.Fatalf("outcome %+v", out)
		}
		if sent := e.ep.sent(); len(sent) != 1 {
			t.Fatalf("%d calls", len(sent))
		}
		if b := e.ep.bearers; !slices.Equal(b, []string{"fake-at-acct-alice"}) {
			t.Fatalf("bearers %v", b)
		}
		if d := e.dispatches(); !slices.Equal(d, []string{"ok"}) {
			t.Fatalf("dispatches %v", d)
		}
		if st := e.approvalState(a.ID); st != "done/erased" {
			t.Fatalf("approval %s", st)
		}
		if n := e.notices(); !slices.Equal(n, []string{"write_done"}) {
			t.Fatalf("notices %v", n)
		}
		st, rows := e.writeAudit()
		if !slices.Equal(st, []string{"dispatching", "ok"}) {
			t.Fatalf("audit %v", st)
		}
		for i, r := range rows {
			want := map[string]string{
				"call": out.DispatchID, "approval": a.ID, "approver": strconv.FormatInt(alice, 10),
				"tier": "approve", "class": "write", "args": a.ArgsSHA, "conn": e.connA.ID,
				"phase": []string{"pre_dispatch", "result"}[i],
			}
			for k, v := range want {
				if got := field(r.peer, k); got != v {
					t.Errorf("audit row %d: %s=%q, want %q (%s)", i, k, got, v, r.peer)
				}
			}
			if tt := field(r.peer, "taint"); tt != "clean" && tt != "external" {
				t.Errorf("audit row %d: taint=%q", i, tt)
			}
			if strings.Contains(r.peer, "Carol") || strings.Contains(r.peer, "fake-at-") {
				t.Errorf("audit row %d carries arguments or a token: %s", i, r.peer)
			}
		}
		if field(rows[1].peer, "result") != shaHex(out.Output) {
			t.Errorf("result digest %s", rows[1].peer)
		}
		// A second dispatch of the same approval sends nothing (S2-A1).
		again := e.dispatch(a.ID)
		if again.Status != connector.StatusRefused || again.Reason != connector.ReasonApprovalConsumed || len(e.ep.sent()) != 1 {
			t.Fatalf("second dispatch %+v, %d calls", again, len(e.ep.sent()))
		}
		if n := e.notices(); !slices.Equal(n, []string{"write_done"}) {
			t.Fatalf("notices after a second dispatch %v", n)
		}
	})
}

// TestS2D7_ApprovedBytesAreSentVerbatim is S2-D7 at the executor: the
// bytes handed to the endpoint are the canonical bytes the approval
// sealed, byte for byte, and they hash to the approval's args_sha.
func TestS2D7_ApprovedBytesAreSentVerbatim(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newWriteEnv(t, s, nil)
		a := e.approved(writeArgs)
		if out := e.dispatch(a.ID); out.Status != connector.StatusOK {
			t.Fatalf("outcome %+v", out)
		}
		sent := e.ep.sent()
		if len(sent) != 1 {
			t.Fatalf("%d calls", len(sent))
		}
		if string(sent[0]) != writeArgs {
			t.Fatalf("sent %q, approved %q", sent[0], writeArgs)
		}
		if shaHex(sent[0]) != a.ArgsSHA {
			t.Fatalf("sent bytes hash to %s, the approval binds %s", shaHex(sent[0]), a.ArgsSHA)
		}
	})
}

// TestS2A3_ChangedArgumentsAreRefused is S2-A3: stored arguments that are
// not the ones the card's args_sha names are refused inside the
// pre-dispatch transaction, after the pre-dispatch audit entry, and
// nothing is sent.
func TestS2A3_ChangedArgumentsAreRefused(t *testing.T) {
	const other = `{"text":"something else","to":"Dana"}`
	cases := []struct {
		name   string
		tamper func(e *writeEnv, a approval.Approval)
		reason string
	}{
		// A blob that opens under the row's own additional data but holds
		// other arguments: only recomputing the hash sees it.
		{"other arguments under the same hash", func(e *writeEnv, a approval.Approval) {
			e.setSealed(a.ID, forgeSeal(e.t, alice, a.ID, a.ArgsSHA, []byte(other)))
		}, connector.ReasonArgsChanged},
		// The hash on the row changed: the blob no longer opens.
		{"args_sha changed", func(e *writeEnv, a approval.Approval) {
			if _, err := e.store.DB.Exec(`UPDATE pa_approvals SET args_sha = $1 WHERE principal = $2 AND id = $3`,
				shaHex([]byte(other)), alice, a.ID); err != nil {
				e.t.Fatal(err)
			}
		}, connector.ReasonApprovalUnreadable},
		// Another approval's blob moved into this row.
		{"blob of another approval", func(e *writeEnv, a approval.Approval) {
			b, err := approval.New(e.binding(shaHex([]byte(other))), e.h.Now())
			if err != nil {
				e.t.Fatal(err)
			}
			if b, err = e.sealer.Seal(b, []byte(other)); err != nil {
				e.t.Fatal(err)
			}
			e.setSealed(a.ID, b.SealedArgs)
		}, connector.ReasonApprovalUnreadable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newWriteEnv(t, s, nil)
				a := e.approved(writeArgs)
				tc.tamper(e, a)
				// The row the executor reads is the tampered one.
				if tc.name == "args_sha changed" {
					a.ArgsSHA = shaHex([]byte(other))
				}
				e.wantNotSent(e.dispatch(a.ID), a, tc.reason)
				if st, _ := e.writeAudit(); !slices.Equal(st, []string{"dispatching", "refused"}) {
					t.Fatalf("audit %v: the refusal must close the pre-dispatch entry (S1-U2)", st)
				}
			})
		})
	}
}

// TestS2A3_NonCanonicalStoredBytesAreRefused: bytes that do hash to
// args_sha but are not in canonical form are not sent either. They would
// be sent as they are, and the card shows the canonical form.
func TestS2A3_NonCanonicalStoredBytesAreRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newWriteEnv(t, s, nil)
		loose := []byte(`{"to":"Carol", "text":"hi"}`)
		a, err := approval.New(e.binding(shaHex(loose)), e.h.Now())
		if err != nil {
			t.Fatal(err)
		}
		a.SealedArgs = forgeSeal(t, alice, a.ID, a.ArgsSHA, loose)
		e.save(a)
		e.wantNotSent(e.dispatch(a.ID), a, connector.ReasonArgsChanged)
	})
}

// staleConsent leaves Alice with a consent record of an older text: not
// withdrawn (which erases her approvals), but no longer satisfied.
// disabledRow records an admin disable of Alice without what
// SetPAPrincipalDisabled does to her approvals in the same transaction.
func (e *writeEnv) disabledRow() {
	if _, err := e.store.DB.Exec(
		`INSERT INTO pa_principal_disables(principal, disabled_at_ms, disabled_by, reason) VALUES($1, $2, $3, 'test')`,
		alice, e.h.Now().UnixMilli(), bob); err != nil {
		e.t.Error(err)
	}
}

func (e *writeEnv) staleConsent() {
	e.t.Helper()
	if _, err := e.store.DB.Exec(`UPDATE pa_consents SET version = 'v0-test' WHERE principal = $1`, alice); err != nil {
		e.t.Error(err)
	}
}

func (e *writeEnv) setSealed(id string, blob []byte) {
	e.t.Helper()
	if _, err := e.store.DB.Exec(`UPDATE pa_approvals SET sealed_args = $1 WHERE principal = $2 AND id = $3`, blob, alice, id); err != nil {
		e.t.Fatal(err)
	}
}

// TestS2F3_WritesFlagIsReadAtDispatch is S2-F3: PA_WRITES_ENABLED off, or
// unreadable, refuses an approval that was made and approved while it was
// on. The flag is read at dispatch and again inside the pre-dispatch
// transaction; the value at approval time is never used.
func TestS2F3_WritesFlagIsReadAtDispatch(t *testing.T) {
	on := connector.Flags{ExternalTools: true, Writes: true, Servers: map[string]bool{"tg": true}}
	off := on
	off.Writes = false
	unreadable := off
	unreadable.WritesErr = errors.New("PA_WRITES_ENABLED: not a boolean")
	unreadableOn := on
	unreadableOn.WritesErr = errors.New("PA_WRITES_ENABLED: not a boolean")
	serverOff := connector.Flags{ExternalTools: true, Writes: true, Servers: map[string]bool{"tg": false}}
	cases := []struct {
		name string
		// set runs after the approval was approved.
		set func(e *writeEnv)
		// inFlight: the flag changes after the executor's first read.
		inFlight bool
		reason   string
	}{
		{"off before dispatch", func(e *writeEnv) { e.flags.Store(&off) }, false, connector.ReasonWritesOff},
		{"unreadable before dispatch", func(e *writeEnv) { e.flags.Store(&unreadable) }, false, connector.ReasonWritesOff},
		{"error with a true value", func(e *writeEnv) { e.flags.Store(&unreadableOn) }, false, connector.ReasonWritesOff},
		{"flags not readable", func(e *writeEnv) { e.flagErr.Store(true) }, false, connector.ReasonFlagOff},
		{"server flag off", func(e *writeEnv) { e.flags.Store(&serverOff) }, false, connector.ReasonFlagOff},
		{"off between the first read and the transaction", func(e *writeEnv) {
			e.fresh.hook = func() { e.flags.Store(&off) }
		}, true, connector.ReasonWritesOff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newWriteEnv(t, s, nil)
				a := e.approved(writeArgs)
				tc.set(e)
				e.wantNotSent(e.dispatch(a.ID), a, tc.reason)
				if asked := e.fresh.asked(); (asked > 0) != tc.inFlight {
					t.Fatalf("tools/list asked %d times", asked)
				}
				// Turning the flag back on does not revive the approval.
				e.fresh.hook = nil
				e.flagErr.Store(false)
				e.flags.Store(&on)
				if out := e.dispatch(a.ID); out.Status != connector.StatusRefused || len(e.ep.sent()) != 0 {
					t.Fatalf("refused approval dispatched after the flag came back: %+v", out)
				}
			})
		})
	}
}

// TestS2C11_UnknownOutcomeIsNeverRetried is S2-C11: a call that was sent
// and did not come back with a readable answer is outcome_unknown. It is
// sent exactly once, the principal is told it may or may not have
// happened, and the approval cannot be dispatched again.
func TestS2C11_UnknownOutcomeIsNeverRetried(t *testing.T) {
	cases := []struct {
		name string
		set  func(ep *writeEP)
		cfg  func(*connector.WriteConfig)
	}{
		{"timeout", func(ep *writeEP) { ep.block = true },
			func(c *connector.WriteConfig) { c.CallTimeout = time.Second }},
		{"transport error", func(ep *writeEP) { ep.err = errors.New("read tcp: connection reset by peer") }, nil},
		{"deadline error", func(ep *writeEP) { ep.err = context.DeadlineExceeded }, nil},
		{"http 502", func(ep *writeEP) { ep.err = fmt.Errorf("%w: status 502", connector.ErrMCPProtocol) }, nil},
		{"http 504", func(ep *writeEP) { ep.err = fmt.Errorf("%w: status 504", connector.ErrMCPProtocol) }, nil},
		{"unreadable result", func(ep *writeEP) { ep.out = []byte(`{"content":`) }, nil},
		{"upstream did not respond", func(ep *writeEP) {
			ep.out = []byte(`{"isError":true,"content":[{"type":"text","text":"The service did not respond within 30s"}]}`)
		}, nil},
		{"upstream gateway timeout", func(ep *writeEP) {
			ep.out = []byte(`{"isError":true,"content":[{"type":"text","text":"APIError 504: upstream"}]}`)
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newWriteEnv(t, s, tc.cfg)
				tc.set(e.ep)
				a := e.approved(writeArgs)
				out := e.dispatch(a.ID)
				if out.Status != connector.StatusOutcomeUnknown || out.Reason != connector.ReasonOutcomeUnknown || out.Output != nil {
					t.Fatalf("outcome %+v, want outcome_unknown without output", out)
				}
				if n := len(e.ep.sent()); n != 1 {
					t.Fatalf("%d tools/call sent, want exactly 1 (no retry)", n)
				}
				if d := e.dispatches(); !slices.Equal(d, []string{"outcome_unknown"}) {
					t.Fatalf("dispatches %v", d)
				}
				if st := e.approvalState(a.ID); st != "done/erased" {
					t.Fatalf("approval %s", st)
				}
				if n := e.notices(); !slices.Equal(n, []string{"write_outcome_unknown"}) {
					t.Fatalf("notices %v", n)
				}
				if st, _ := e.writeAudit(); !slices.Equal(st, []string{"dispatching", "outcome_unknown"}) {
					t.Fatalf("audit %v", st)
				}
				// Asking again, with the server healthy, sends nothing.
				e.ep.mu.Lock()
				e.ep.block, e.ep.err, e.ep.out = false, nil, nil
				e.ep.mu.Unlock()
				again := e.dispatch(a.ID)
				if again.Status != connector.StatusRefused || again.Reason != connector.ReasonApprovalConsumed {
					t.Fatalf("second dispatch %+v", again)
				}
				if n := len(e.ep.sent()); n != 1 {
					t.Fatalf("%d tools/call after a second dispatch", n)
				}
			})
		})
	}
}

// TestWriteDispatch_KnownOutcomes: a tool error that names no silence
// upstream is tool_error, and a server that refuses the token ran nothing.
// Neither is retried.
func TestWriteDispatch_KnownOutcomes(t *testing.T) {
	cases := []struct {
		name     string
		set      func(ep *writeEP)
		status   connector.Status
		dispatch string
		notice   string
	}{
		{"tool error", func(ep *writeEP) {
			ep.out = []byte(`{"isError":true,"content":[{"type":"text","text":"chat not found"}]}`)
		}, connector.StatusToolError, "tool_error", "write_failed"},
		{"token refused", func(ep *writeEP) { ep.err = connector.ErrMCPTokenRejected },
			connector.StatusRefused, "refused", "write_not_sent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newWriteEnv(t, s, nil)
				tc.set(e.ep)
				a := e.approved(writeArgs)
				out := e.dispatch(a.ID)
				if out.Status != tc.status || len(e.ep.sent()) != 1 {
					t.Fatalf("outcome %+v, %d calls", out, len(e.ep.sent()))
				}
				if d := e.dispatches(); !slices.Equal(d, []string{tc.dispatch}) {
					t.Fatalf("dispatches %v", d)
				}
				if n := e.notices(); !slices.Equal(n, []string{tc.notice}) {
					t.Fatalf("notices %v", n)
				}
			})
		})
	}
}

// TestS2C13_ResultAfterDisconnectIsFenced is S2-C13: a /disconnect that
// lands while the call is in flight returns without waiting for it (the
// executor holds no transaction and no row lock then), and the result that
// arrives afterwards is discarded as fenced. The same holds for consent
// withdrawn, the principal disabled and the conversation closed meanwhile.
// The principal is told the action may already have happened.
func TestS2C13_ResultAfterDisconnectIsFenced(t *testing.T) {
	cases := []struct {
		name string
		// during runs inside the fake server's tools/call.
		during func(e *writeEnv)
	}{
		{"disconnect", func(e *writeEnv) {
			done := make(chan error, 1)
			go func() {
				_, err := e.mgr.Disconnect(context.Background(), alice, e.connA.ID)
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					e.t.Errorf("disconnect: %v", err)
				}
			case <-time.After(3 * time.Second):
				e.t.Error("disconnect waited for the in-flight call")
			}
		}},
		{"consent withdrawn", func(e *writeEnv) {
			e.inTx(func(tx *sql.Tx) error {
				return e.store.WithdrawPAConsent(context.Background(), tx, alice, e.h.Now())
			})
		}},
		{"principal disabled", func(e *writeEnv) {
			if err := e.store.SetPAPrincipalDisabled(context.Background(), alice, bob, "test", e.h.Now()); err != nil {
				e.t.Error(err)
			}
		}},
		{"conversation closed", func(e *writeEnv) {
			e.inTx(func(tx *sql.Tx) error {
				return e.store.ClosePAConversations(context.Background(), tx, alice, e.h.Now())
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newWriteEnv(t, s, nil)
				a := e.approved(writeArgs)
				// The server answers with a success after the change.
				e.ep.onCall = func() { tc.during(e) }
				out := e.dispatch(a.ID)
				if out.Status != connector.StatusFenced || out.Reason != connector.ReasonFenced || out.Output != nil {
					t.Fatalf("outcome %+v, want fenced without output", out)
				}
				if n := len(e.ep.sent()); n != 1 {
					t.Fatalf("%d calls", n)
				}
				if d := e.dispatches(); !slices.Equal(d, []string{"fenced"}) {
					t.Fatalf("dispatches %v", d)
				}
				if n := e.notices(); !slices.Equal(n, []string{"write_fenced"}) {
					t.Fatalf("notices %v", n)
				}
				st, rows := e.writeAudit()
				if !slices.Equal(st, []string{"dispatching", "fenced"}) || field(rows[1].peer, "result") != "-" {
					t.Fatalf("audit %v %+v", st, rows)
				}
			})
		})
	}
}

// TestS2A1_ExecutorConsumesBeforeTheCall is S2-A1 at the executor: when
// the request reaches the server the receipt is already consumed and
// committed, so a second dispatch of the same approval that arrives during
// the call (a double tap, another replica) is refused and sends nothing.
func TestS2A1_ExecutorConsumesBeforeTheCall(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newWriteEnv(t, s, nil)
		a := e.approved(writeArgs)
		var during string
		var second connector.WriteOutcome
		e.ep.onCall = func() {
			if during != "" {
				return
			}
			during = e.approvalState(a.ID) + " " + strings.Join(e.dispatches(), ",")
			second = e.dispatch(a.ID)
		}
		out := e.dispatch(a.ID)
		if during != "dispatching/erased dispatching" {
			t.Fatalf("during the call the approval and its record were %q, want both dispatching", during)
		}
		if second.Status != connector.StatusRefused || second.Reason != connector.ReasonApprovalConsumed {
			t.Fatalf("second dispatch during the call: %+v", second)
		}
		if n := len(e.ep.sent()); n != 1 {
			t.Fatalf("%d tools/call sent, want 1", n)
		}
		if out.Status != connector.StatusOK || !slices.Equal(e.dispatches(), []string{"ok"}) {
			t.Fatalf("first dispatch %+v, records %v", out, e.dispatches())
		}
		if n := e.notices(); !slices.Equal(n, []string{"write_done"}) {
			t.Fatalf("notices %v", n)
		}
	})
}

// TestWriteDispatch_ConnectionRevokedBeforeTheTransaction: a /disconnect
// that lands after the executor's first checks and before its transaction
// is seen by the locked re-read of the connection there (S2-C10 at the
// executor): nothing is sent and no dispatch record exists.
// A /disconnect on this replica cancels the registered call as well and is
// refused one step earlier, before the pre-dispatch entry.
func TestWriteDispatch_ConnectionRevokedBeforeTheTransaction(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newWriteEnv(t, s, nil)
		a := e.approved(writeArgs)
		// Revoked in the store, as another replica's /disconnect does it:
		// this process's call is not cancelled, only the row says so.
		e.fresh.hook = func() {
			if _, _, _, err := s.RevokePAConnection(context.Background(), alice, e.connA.ID, "disconnect"); err != nil {
				t.Error(err)
			}
		}
		out := e.dispatch(a.ID)
		if out.Status != connector.StatusRefused || out.Reason != connector.ReasonConnectionInactive {
			t.Fatalf("outcome %+v, want refused connection_inactive", out)
		}
		if len(e.ep.sent()) != 0 || len(e.dispatches()) != 0 {
			t.Fatalf("%d calls, records %v", len(e.ep.sent()), e.dispatches())
		}
		if st := e.approvalState(a.ID); !strings.HasSuffix(st, "/erased") || strings.HasPrefix(st, "approved") {
			t.Fatalf("approval %s, want ended with its arguments erased", st)
		}
		if st, _ := e.writeAudit(); !slices.Equal(st, []string{"dispatching", "refused"}) {
			t.Fatalf("audit %v", st)
		}
	})
}

// TestWriteDispatch_CallerGoneBeforeTheRequest: a dispatch whose caller
// went away before anything was sent is refused as not sent; it is not
// reported as an unknown outcome.
func TestWriteDispatch_CallerGoneBeforeTheRequest(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newWriteEnv(t, s, nil)
		a := e.approved(writeArgs)
		ctx, cancel := context.WithCancel(context.Background())
		e.fresh.hook = cancel
		out, err := e.x.DispatchApproved(ctx, alice, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		e.wantNotSent(out, a, connector.ReasonDispatchCancelled)
	})
}

func TestWriteDispatch_DisconnectBeforeTheRequest(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newWriteEnv(t, s, nil)
		a := e.approved(writeArgs)
		e.fresh.hook = func() {
			if _, err := e.mgr.Disconnect(context.Background(), alice, e.connA.ID); err != nil {
				t.Error(err)
			}
		}
		out := e.dispatch(a.ID)
		if out.Status != connector.StatusRefused || out.Reason != connector.ReasonConnectionInactive ||
			len(e.ep.sent()) != 0 || len(e.dispatches()) != 0 {
			t.Fatalf("outcome %+v, %d calls, records %v", out, len(e.ep.sent()), e.dispatches())
		}
		if st, _ := e.writeAudit(); !slices.Equal(st, []string{"refused"}) {
			t.Fatalf("audit %v", st)
		}
	})
}

// TestWriteDispatch_NoTransactionDuringTheCall: while the request is at
// the server the executor holds no database connection at all, so no
// transaction and no lock (threat model T2: "no transaction is open during
// the call").
func TestWriteDispatch_NoTransactionDuringTheCall(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newWriteEnv(t, s, nil)
		a := e.approved(writeArgs)
		inUse := -1
		e.ep.onCall = func() { inUse = s.DB.Stats().InUse }
		if out := e.dispatch(a.ID); out.Status != connector.StatusOK {
			t.Fatalf("outcome %+v", out)
		}
		if inUse != 0 {
			t.Fatalf("%d database connections in use during tools/call, want 0", inUse)
		}
	})
}

// TestWriteDispatch_Refusals: each check before the receipt is consumed
// refuses, sends nothing, ends the approval and says so.
func TestWriteDispatch_Refusals(t *testing.T) {
	cases := []struct {
		name   string
		set    func(e *writeEnv)
		reason string
	}{
		{"no fresh surface", nil, connector.ReasonNoWritePath},
		{"fresh listing failed", func(e *writeEnv) { e.fresh.err = errors.New("tools/list failed") }, ""},
		{"schema drifted", func(e *writeEnv) { e.fresh.tool.SchemaSHA = shaHex([]byte("new schema")) }, connector.ReasonToolChanged},
		{"description drifted", func(e *writeEnv) { e.fresh.tool.DescriptionSHA = shaHex([]byte("new")) }, connector.ReasonToolChanged},
		{"annotations drifted", func(e *writeEnv) { e.fresh.tool.AnnotationSHA = shaHex([]byte("new")) }, connector.ReasonToolChanged},
		{"class changed", func(e *writeEnv) { e.fresh.tool.Class = catalog.ClassDisclosure }, connector.ReasonToolChanged},
		{"tier lowered", func(e *writeEnv) { e.fresh.tool.Tier = catalog.TierAuto }, connector.ReasonToolChanged},
		{"principal off the allowlist", func(e *writeEnv) { e.denied.Store(true) }, connector.ReasonPrincipalNotAllowed},
		// The disable row alone: SetPAPrincipalDisabled also cancels the
		// approvals it finds (S2-C9, TestS2C9_CancelledCardAnswersCancelled),
		// so the executor's own check is what refuses an approval that the
		// disable did not see, one committed concurrently with it.
		{"principal disabled", func(e *writeEnv) { e.disabledRow() }, connector.ReasonPrincipalDisabled},
		{"consent not the current version", func(e *writeEnv) { e.staleConsent() }, connector.ReasonConsentGone},
		{"audit unavailable", func(e *writeEnv) { e.sink.fail.Store(true) }, connector.ReasonAuditUnavailable},
		{"consent stale after the first read", func(e *writeEnv) {
			e.fresh.hook = e.staleConsent
		}, connector.ReasonConsentGone},
		{"disabled after the first read", func(e *writeEnv) { e.fresh.hook = e.disabledRow }, connector.ReasonPrincipalDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				var mutate func(*connector.WriteConfig)
				if tc.name == "no fresh surface" {
					mutate = func(c *connector.WriteConfig) { c.Fresh = nil }
				}
				e := newWriteEnv(t, s, mutate)
				a := e.approved(writeArgs)
				if tc.set != nil {
					tc.set(e)
				}
				out := e.dispatch(a.ID)
				if tc.name == "audit unavailable" {
					// Nothing can be appended: only the outcome and the
					// rows say it.
					e.sink.fail.Store(false)
					if out.Status != connector.StatusRefused || out.Reason != tc.reason || len(e.ep.sent()) != 0 ||
						e.approvalState(a.ID) != "refused/erased" || len(e.dispatches()) != 0 {
						t.Fatalf("outcome %+v", out)
					}
					return
				}
				reason := tc.reason
				if reason == "" {
					reason = out.Reason
					if reason == "" {
						t.Fatalf("outcome %+v", out)
					}
				}
				e.wantNotSent(out, a, reason)
			})
		})
	}
}

// TestS2A6_ListingRefusalAtDispatchIsCounted: a write that the executor's
// own tools/list refused is counted in
// mctl_pa_write_listing_refusals_total under the reason of the refusal,
// and under no other. Every reason of the endpoint exists at 0 before the
// first refusal, and a dispatch that the listing let through, or one
// refused before any listing was asked, counts nothing.
func TestS2A6_ListingRefusalAtDispatchIsCounted(t *testing.T) {
	series := func(reg *metrics.Registry) map[string]float64 {
		out := map[string]float64{}
		for _, r := range connector.WriteListingRefusalReasons {
			if v := testutil.ToFloat64(reg.PAWriteListingRefusals.WithLabelValues("tg", r)); v != 0 {
				out[r] = v
			}
		}
		return out
	}
	cases := []struct {
		name string
		set  func(e *writeEnv)
		want map[string]float64
	}{
		{"the server cannot be listed", func(e *writeEnv) { e.fresh.err = catalog.ErrServerUnavailable },
			map[string]float64{connector.ReasonServerUnavailable: 1}},
		{"the listing is unusable", func(e *writeEnv) { e.fresh.err = catalog.ErrListingStale },
			map[string]float64{connector.ReasonListingStale: 1}},
		{"the tool is gone from the listing", func(e *writeEnv) { e.fresh.err = catalog.ErrNotPinned },
			map[string]float64{connector.ReasonNotPinned: 1}},
		{"the listed tool is not the pinned one", func(e *writeEnv) { e.fresh.err = catalog.ErrToolChanged },
			map[string]float64{connector.ReasonToolChanged: 1}},
		{"an error the executor does not know", func(e *writeEnv) { e.fresh.err = errors.New("tools/list failed") },
			map[string]float64{connector.ReasonInternal: 1}},
		{"the listed tool is not the one on the card", func(e *writeEnv) { e.fresh.tool.SchemaSHA = shaHex([]byte("new schema")) },
			map[string]float64{connector.ReasonToolChanged: 1}},
		{"the listing agrees", nil, map[string]float64{}},
		{"refused before the listing", func(e *writeEnv) { e.denied.Store(true) }, map[string]float64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				reg := metrics.New()
				e := newWriteEnv(t, s, func(c *connector.WriteConfig) { c.Metrics = reg })
				if n := testutil.CollectAndCount(reg.PAWriteListingRefusals); n != len(connector.WriteListingRefusalReasons) {
					t.Fatalf("%d series before the first dispatch, want one per reason (%d)", n, len(connector.WriteListingRefusalReasons))
				}
				if got := series(reg); len(got) != 0 {
					t.Fatalf("counted before any dispatch: %v", got)
				}
				a := e.approved(writeArgs)
				if tc.set != nil {
					tc.set(e)
				}
				out := e.dispatch(a.ID)
				if got := series(reg); !maps.Equal(got, tc.want) {
					t.Fatalf("listing refusals %v, want %v (outcome %+v)", got, tc.want, out)
				}
				for reason := range tc.want {
					if out.Status != connector.StatusRefused || out.Reason != reason || len(e.ep.sent()) != 0 {
						t.Fatalf("outcome %+v, want refused %s with nothing sent", out, reason)
					}
					// The same refusal stays in the dispatch counter.
					if v := testutil.ToFloat64(reg.PADispatchTotal.WithLabelValues("tg", "refused", reason)); v != 1 {
						t.Fatalf("dispatch counter for %s is %v, want 1", reason, v)
					}
				}
			})
		})
	}
}

// TestS2A6_ListingRefusalAtTheCardIsCounted: a call that the listing read
// for its card refused is counted in the executor's counter under the
// reason of the refusal; a call whose card was made counts nothing.
func TestS2A6_ListingRefusalAtTheCardIsCounted(t *testing.T) {
	cases := []struct {
		name   string
		set    func(e *cardEnv)
		reason string
	}{
		{"the server cannot be listed", func(e *cardEnv) { e.fresh.err = catalog.ErrServerUnavailable }, connector.ReasonServerUnavailable},
		{"the listed tool is not the pinned one", func(e *cardEnv) { e.fresh.err = catalog.ErrToolChanged }, connector.ReasonToolChanged},
		{"the listed tool is of another class", func(e *cardEnv) { e.fresh.tool.Class = catalog.ClassRead }, connector.ReasonToolChanged},
		{"the listing agrees", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := metrics.New()
			e := newCardEnvOn(t, sqliteStore(t), cardPin(), nil, func(c *connector.CardConfig) { c.Metrics = reg })
			if tc.set != nil {
				tc.set(e)
			}
			a := e.call(e.token, writeCall(writeArgs))
			e.h.Loop().WaitDeliveries()
			total := 0.0
			for _, r := range connector.WriteListingRefusalReasons {
				v := testutil.ToFloat64(reg.PAWriteListingRefusals.WithLabelValues("tg", r))
				if r == tc.reason && v != 1 {
					t.Fatalf("%s counted %v times (answer %+v)", r, v, a)
				}
				total += v
			}
			if tc.reason == "" {
				if total != 0 || a.Status != connector.StatusApprovalPending {
					t.Fatalf("a made card: %v counted, answer %+v", total, a)
				}
				return
			}
			if total != 1 || !strings.Contains(a.raw, tc.reason) {
				t.Fatalf("%v counted in all, answer %+v, want one %s", total, a, tc.reason)
			}
			e.nothingWritten()
		})
	}
}

// TestWriteDispatch_NotApproved: an approval nobody approved, another
// principal's approval and an unknown id are refused without a call, and
// a pending approval is left pending for its card.
func TestWriteDispatch_NotApproved(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newWriteEnv(t, s, nil)
		ctx := context.Background()
		canon := []byte(writeArgs)
		p, err := approval.New(e.binding(shaHex(canon)), e.h.Now())
		if err != nil {
			t.Fatal(err)
		}
		if p, err = e.sealer.Seal(p, canon); err != nil {
			t.Fatal(err)
		}
		e.inTx(func(tx *sql.Tx) error { return e.store.CreatePAApproval(ctx, tx, p) })
		if out := e.dispatch(p.ID); out.Status != connector.StatusRefused || out.Reason != connector.ReasonApprovalNotApproved {
			t.Fatalf("pending: %+v", out)
		}
		if st := e.approvalState(p.ID); st != "pending" {
			t.Fatalf("pending approval became %s", st)
		}

		a := e.approved(writeArgs)
		// Bob dispatching Alice's approval id reads as not found (I10).
		out, err := e.x.DispatchApproved(ctx, bob, a.ID)
		if err != nil || out.Status != connector.StatusRefused || out.Reason != connector.ReasonApprovalNotFound {
			t.Fatalf("other principal: %+v %v", out, err)
		}
		if st := e.approvalState(a.ID); st != "approved" {
			t.Fatalf("Alice's approval became %s after Bob's attempt", st)
		}
		if out := e.dispatch(approval.NewID()); out.Reason != connector.ReasonApprovalNotFound {
			t.Fatalf("unknown id: %+v", out)
		}
		if _, err := e.x.DispatchApproved(ctx, 0, a.ID); !errors.Is(err, connector.ErrInvalidCall) {
			t.Fatalf("no principal: %v", err)
		}
		if n := len(e.ep.sent()); n != 0 {
			t.Fatalf("%d calls", n)
		}
		if n := e.notices(); len(n) != 0 {
			t.Fatalf("notices %v", n)
		}

		// Expired: refused before anything is asked of the server, ended,
		// and the principal is told.
		e.h.Advance(approval.TTL + time.Minute)
		e.wantNotSent(e.dispatch(a.ID), a, connector.ReasonApprovalExpired)
		if e.fresh.asked() != 0 {
			t.Fatal("tools/list asked for an expired approval")
		}
	})
}

// TestS2C12_StaleSweepOwnsTheRecord: a dispatch record whose
// executor is gone (S2-C12) is resolved by the sweeper to outcome_unknown
// with the audit result entry and the "may or may not have happened"
// notice, once; and an executor that comes back late writes nothing more.
func TestS2C12_StaleSweepOwnsTheRecord(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newWriteEnv(t, s, func(c *connector.WriteConfig) { c.CallTimeout = time.Second })
		sweeper := connector.StaleWriteSweeper{Store: s, Executor: &connector.Executor{Sink: e.sink, Now: e.h.Now}}
		a := e.approved(writeArgs)
		// The call returns after its lease ran out and the sweep ran: the
		// executor finds its record already resolved.
		swept := -1
		e.ep.onCall = func() {
			if n, err := sweeper.SweepOnce(context.Background()); err != nil || n != 0 {
				t.Errorf("sweep inside the lease: %d %v", n, err)
			}
			e.h.Advance(approval.MaxDispatchLease + time.Minute)
			n, err := sweeper.SweepOnce(context.Background())
			if err != nil {
				t.Errorf("sweep: %v", err)
			}
			swept = n
		}
		out := e.dispatch(a.ID)
		if swept != 1 {
			t.Fatalf("swept %d records, want 1", swept)
		}
		if out.Status != connector.StatusOutcomeUnknown || out.Output != nil {
			t.Fatalf("late executor outcome %+v", out)
		}
		if d := e.dispatches(); !slices.Equal(d, []string{"outcome_unknown"}) {
			t.Fatalf("dispatches %v", d)
		}
		if n := e.notices(); !slices.Equal(n, []string{"write_outcome_unknown"}) {
			t.Fatalf("notices %v, want exactly one", n)
		}
		st, rows := e.writeAudit()
		if !slices.Equal(st, []string{"dispatching", "outcome_unknown"}) {
			t.Fatalf("audit %v, want one pre-dispatch and one result entry", st)
		}
		if field(rows[0].peer, "call") != field(rows[1].peer, "call") || field(rows[1].peer, "approval") != a.ID ||
			field(rows[1].peer, "reason") != connector.ReasonLeaseExpired {
			t.Fatalf("sweep result entry %s", rows[1].peer)
		}
		if n, err := sweeper.SweepOnce(context.Background()); err != nil || n != 0 {
			t.Fatalf("second sweep: %d %v", n, err)
		}
	})
}

// markFaultStore is the ledger with a sent mark the test decides: mark,
// when set, stands in for MarkPADispatchSent; finishErr fails every
// FinishPADispatch, so a call that was not sent cannot be settled by its
// executor.
type markFaultStore struct {
	*db.Store
	mark      func(ctx context.Context, principal int64, dispatchID string, now time.Time) error
	finishErr error
}

func (m *markFaultStore) MarkPADispatchSent(ctx context.Context, principal int64, dispatchID string, now time.Time) error {
	if m.mark != nil {
		return m.mark(ctx, principal, dispatchID, now)
	}
	return m.Store.MarkPADispatchSent(ctx, principal, dispatchID, now)
}

func (m *markFaultStore) FinishPADispatch(ctx context.Context, tx *sql.Tx, principal int64, dispatchID string, status approval.DispatchStatus, now time.Time) (approval.Dispatch, error) {
	if m.finishErr != nil {
		return approval.Dispatch{}, m.finishErr
	}
	return m.Store.FinishPADispatch(ctx, tx, principal, dispatchID, status, now)
}

// TestS2C12_CommittedAndNeverSentIsNotUnknown: a dispatch whose record was
// committed, whose request was never made and which its executor could
// not settle is ended by the sweep under a reason of its own. The record
// is refused, the audit result entry says dispatch_never_sent and the
// principal is told the action was not carried out, not that it may have
// happened. Two ways there: the sent mark could not be written, and the
// lease ran out before the mark.
func TestS2C12_CommittedAndNeverSentIsNotUnknown(t *testing.T) {
	for _, tc := range []struct {
		name       string
		wantReason string
		arrange    func(e *writeEnv, fs *markFaultStore, sweeper connector.StaleWriteSweeper)
	}{
		{"the mark cannot be written", connector.ReasonStateUnreadable,
			func(_ *writeEnv, fs *markFaultStore, _ connector.StaleWriteSweeper) {
				fs.mark = func(context.Context, int64, string, time.Time) error {
					return fmt.Errorf("%w: injected", approval.ErrUnreadable)
				}
				fs.finishErr = fmt.Errorf("%w: injected", approval.ErrUnreadable)
			}},
		{"the lease ran out before the mark", connector.ReasonNeverSent,
			func(e *writeEnv, fs *markFaultStore, sweeper connector.StaleWriteSweeper) {
				fs.mark = func(ctx context.Context, principal int64, id string, _ time.Time) error {
					e.h.Advance(approval.MaxDispatchLease + time.Minute)
					if n, err := sweeper.SweepOnce(ctx); err != nil || n != 1 {
						e.t.Errorf("sweep before the mark: %d %v, want 1", n, err)
					}
					return fs.Store.MarkPADispatchSent(ctx, principal, id, e.h.Now())
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				fs := &markFaultStore{Store: s}
				e := newWriteEnv(t, s, func(c *connector.WriteConfig) { c.Store = fs; c.CallTimeout = time.Second })
				sweeper := connector.StaleWriteSweeper{Store: s, Executor: &connector.Executor{Sink: e.sink, Now: e.h.Now}}
				tc.arrange(e, fs, sweeper)
				a := e.approved(writeArgs)
				out := e.dispatch(a.ID)
				if out.Status != connector.StatusRefused || out.Reason != tc.wantReason || out.Output != nil {
					t.Fatalf("outcome %+v, want refused (%s)", out, tc.wantReason)
				}
				if n := len(e.ep.sent()); n != 0 {
					t.Fatalf("%d calls were sent for a dispatch that was not marked as sent", n)
				}
				// The executor could not settle the first; the sweep does,
				// once its lease has run out.
				fs.mark, fs.finishErr = nil, nil
				e.h.Advance(approval.MaxDispatchLease + time.Minute)
				if _, err := sweeper.SweepOnce(context.Background()); err != nil {
					t.Fatalf("sweep: %v", err)
				}
				if d := e.dispatches(); !slices.Equal(d, []string{"refused"}) {
					t.Fatalf("dispatch records %v, want one refused", d)
				}
				if st := e.approvalState(a.ID); st != "done/erased" {
					t.Fatalf("approval is %s, want done/erased", st)
				}
				if n := e.notices(); !slices.Equal(n, []string{"write_not_sent"}) {
					t.Fatalf("notices %v, want exactly one write_not_sent", n)
				}
				st, rows := e.writeAudit()
				if !slices.Equal(st, []string{"dispatching", "refused"}) {
					t.Fatalf("audit %v, want one pre-dispatch and one refused result entry", st)
				}
				if field(rows[0].peer, "call") != field(rows[1].peer, "call") || field(rows[1].peer, "approval") != a.ID ||
					field(rows[1].peer, "reason") != connector.ReasonNeverSent {
					t.Fatalf("sweep result entry %s, want reason %s", rows[1].peer, connector.ReasonNeverSent)
				}
				// The receipt is spent: a second tap sends nothing.
				if out := e.dispatch(a.ID); out.Status != connector.StatusRefused {
					t.Fatalf("second dispatch %+v", out)
				}
				if n := len(e.ep.sent()); n != 0 {
					t.Fatalf("%d calls after the second dispatch", n)
				}
				if n, err := sweeper.SweepOnce(context.Background()); err != nil || n != 0 {
					t.Fatalf("second sweep: %d %v", n, err)
				}
			})
		})
	}
}

// TestWriteNotices_NeverClaimNothingHappened: the texts for a fenced and
// an unknown outcome say the action may have happened, in both languages,
// and none of the outcome texts carries a placeholder.
func TestWriteNotices_NeverClaimNothingHappened(t *testing.T) {
	for name, tpl := range map[string]safetext.Template{
		"fenced": safetext.TextWriteFenced, "unknown": safetext.TextWriteUnknown,
	} {
		text := tpl.In(safetext.LangEN) + " / " + tpl.In(safetext.LangRU)
		if !strings.Contains(tpl.In(safetext.LangEN), "may") || !strings.Contains(tpl.In(safetext.LangRU), "могло") {
			t.Errorf("%s: %q does not say the action may have happened", name, text)
		}
		for _, bad := range []string{"was not carried out", "nothing was sent", "не выполнено", "ничего не отправлено"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s: %q claims the action did not happen", name, text)
			}
		}
	}
}
