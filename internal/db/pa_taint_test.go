package db

// pa_taint_test.go pins the durable per-conversation taint of threat model
// T5 (#1321) at the store: the flag rises with every external fragment in
// the fragment's transaction, never falls on a row, and resets only through
// a new row. Test names carry the S2 ids of the threat model.

import (
	"context"
	"database/sql"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
)

// taintSealer seals fragments for the store tests; the key is a fixture.
func taintSealer(t *testing.T) *convo.Sealer {
	t.Helper()
	s, err := convo.NewSealer([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// openConv opens (or returns) the principal's conversation at now.
func openConv(t *testing.T, s *Store, p int64, id string, now time.Time) convo.Conversation {
	t.Helper()
	var c convo.Conversation
	must(t, inTx(t, s, func(tx *sql.Tx) error {
		var err error
		c, err = s.OpenPAConversation(context.Background(), tx, p, id, now, 24*time.Hour)
		return err
	}))
	return c
}

// appendFrag stores one fragment of kind/prov in conv.
func appendFrag(t *testing.T, s *Store, sealer *convo.Sealer, p int64, conv string, kind convo.Kind, prov convo.Provenance, text string) {
	t.Helper()
	ctx := context.Background()
	must(t, inTx(t, s, func(tx *sql.Tx) error {
		seq, err := s.NextPAFragmentSeq(ctx, tx, p, conv)
		if err != nil {
			return err
		}
		sf, err := sealer.Seal(p, conv, seq, convo.NewFragment(kind, prov, text))
		if err != nil {
			return err
		}
		sf.CreatedAt = t0
		return s.AppendPAFragment(ctx, tx, sf)
	}))
}

func mustTaint(t *testing.T, s *Store, p int64, conv string) bool {
	t.Helper()
	tainted, err := s.ReadPAConversationTaint(context.Background(), p, conv)
	if err != nil {
		t.Fatalf("read taint: %v", err)
	}
	return tainted
}

// TestS2I6_FragmentKindsTaint: every fragment that is not exactly user text
// taints its conversation, in the fragment's transaction; user text and
// model output do not (owner decision: model output in a clean
// conversation is not taint).
func TestS2I6_FragmentKindsTaint(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		sealer := taintSealer(t)
		cases := []struct {
			name    string
			kind    convo.Kind
			prov    convo.Provenance
			tainted bool
		}{
			{"user text", convo.KindText, convo.ProvenanceUser, false},
			{"model output", convo.KindAssistant, convo.ProvenanceExternal, false},
			{"forwarded text", convo.KindText, convo.ProvenanceExternal, true},
			{"unknown mark", convo.KindText, convo.Provenance("weird"), true},
			{"caption", convo.KindCaption, convo.ProvenanceUser, true},
			{"reply", convo.KindReply, convo.ProvenanceUser, true},
			{"quote", convo.KindQuote, convo.ProvenanceUser, true},
			{"tool output", convo.KindTool, convo.ProvenanceUser, true},
		}
		for i, c := range cases {
			now := t0.Add(time.Duration(i) * 48 * time.Hour)
			// A fresh conversation per case: the previous one expired.
			conv := openConv(t, s, alice, "c-"+strconv.Itoa(i), now)
			if conv.ID != "c-"+strconv.Itoa(i) {
				t.Fatalf("%s: conversation %q reused", c.name, conv.ID)
			}
			if mustTaint(t, s, alice, conv.ID) {
				t.Fatalf("%s: a new conversation starts tainted", c.name)
			}
			appendFrag(t, s, sealer, alice, conv.ID, c.kind, c.prov, "x")
			if got := mustTaint(t, s, alice, conv.ID); got != c.tainted {
				t.Fatalf("%s: tainted = %v, want %v", c.name, got, c.tainted)
			}
		}
	})
}

// TestS2I6_TaintRollsBackWithFragment: the flag and the fragment share the
// transaction, so a rolled-back append leaves neither.
func TestS2I6_TaintRollsBackWithFragment(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		sealer := taintSealer(t)
		conv := openConv(t, s, alice, "c-rb", t0)
		boom := errors.New("rolled back")
		err := inTx(t, s, func(tx *sql.Tx) error {
			sf, err := sealer.Seal(alice, conv.ID, 1, convo.NewFragment(convo.KindText, convo.ProvenanceExternal, "fwd"))
			if err != nil {
				return err
			}
			if err := s.AppendPAFragment(ctx, tx, sf); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatal(err)
		}
		if mustTaint(t, s, alice, conv.ID) {
			t.Fatal("a rolled-back fragment left the conversation tainted")
		}
		appendFrag(t, s, sealer, alice, conv.ID, convo.KindText, convo.ProvenanceExternal, "fwd")
		if !mustTaint(t, s, alice, conv.ID) {
			t.Fatal("a committed external fragment did not taint")
		}
	})
}

// TestS2I7_ResetOnlyThroughNewRow: /new and TTL expiry give a clean new
// row while the old one keeps its flag until the sweep removes it; after
// that the old id reads tainted (not found). Reopening an open, tainted
// conversation keeps it tainted.
func TestS2I7_ResetOnlyThroughNewRow(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		sealer := taintSealer(t)

		old := openConv(t, s, alice, "c-old", t0)
		appendFrag(t, s, sealer, alice, old.ID, convo.KindText, convo.ProvenanceExternal, "fwd")
		if again := openConv(t, s, alice, "c-other", t0.Add(time.Minute)); again.ID != old.ID || !mustTaint(t, s, alice, again.ID) {
			t.Fatalf("reopen: %q tainted=%v, want the tainted %q", again.ID, mustTaint(t, s, alice, again.ID), old.ID)
		}
		// /new.
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.ClosePAConversations(ctx, tx, alice, t0.Add(2*time.Minute)) }))
		fresh := openConv(t, s, alice, "c-new", t0.Add(3*time.Minute))
		if fresh.ID != "c-new" || mustTaint(t, s, alice, fresh.ID) {
			t.Fatalf("after /new: %q tainted=%v, want a clean c-new", fresh.ID, mustTaint(t, s, alice, fresh.ID))
		}
		if !mustTaint(t, s, alice, old.ID) {
			t.Fatal("/new lowered the closed conversation's flag")
		}

		// TTL expiry: bob's tainted conversation expires; the next open
		// is a new, clean row.
		bConv := openConv(t, s, bob, "b-old", t0)
		appendFrag(t, s, sealer, bob, bConv.ID, convo.KindQuote, convo.ProvenanceExternal, "q")
		later := t0.Add(25 * time.Hour)
		if _, err := s.SweepPAState(ctx, later, later.Add(-48*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if tainted, err := s.ReadPAConversationTaint(ctx, bob, bConv.ID); !tainted || !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("swept conversation: tainted=%v err=%v, want tainted and not found", tainted, err)
		}
		bNew := openConv(t, s, bob, "b-new", later)
		if bNew.ID != "b-new" || mustTaint(t, s, bob, bNew.ID) {
			t.Fatalf("after expiry: %q tainted=%v, want a clean b-new", bNew.ID, mustTaint(t, s, bob, bNew.ID))
		}
	})
}

// TestS2I7_ForgetResetsThroughNewRow: /forget deletes the row, so the old
// id reads tainted and the next conversation is a clean new row.
func TestS2I7_ForgetResetsThroughNewRow(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		old := openConv(t, s, alice, "f-old", t0)
		appendFrag(t, s, taintSealer(t), alice, old.ID, convo.KindCaption, convo.ProvenanceExternal, "c")
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.ForgetPAConversations(ctx, tx, alice) }))
		if tainted, err := s.ReadPAConversationTaint(ctx, alice, old.ID); !tainted || !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("forgotten: tainted=%v err=%v", tainted, err)
		}
		if c := openConv(t, s, alice, "f-new", t0.Add(time.Minute)); mustTaint(t, s, alice, c.ID) {
			t.Fatal("after /forget the new conversation is tainted")
		}
	})
}

// TestS2I10_TaintReadFailsClosed: every read that does not observe a
// stored 0 is tainted, with an error where nothing was observed.
func TestS2I10_TaintReadFailsClosed(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		conv := openConv(t, s, alice, "r-1", t0)
		if mustTaint(t, s, alice, conv.ID) {
			t.Fatal("fresh conversation tainted")
		}
		// Another principal's conversation is not found, and tainted.
		if tainted, err := s.ReadPAConversationTaint(ctx, bob, conv.ID); !tainted || !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("other principal: tainted=%v err=%v", tainted, err)
		}
		// Invalid input.
		if tainted, err := s.ReadPAConversationTaint(ctx, alice, ""); !tainted || err == nil {
			t.Fatalf("empty id: tainted=%v err=%v", tainted, err)
		}
		// A value other than 0 or 1 is tainted.
		if _, err := s.DB.Exec(`UPDATE pa_conversations SET tainted = 7 WHERE id = $1`, conv.ID); err != nil {
			t.Fatal(err)
		}
		if !mustTaint(t, s, alice, conv.ID) {
			t.Fatal("tainted = 7 read as clean")
		}
		// A failed read (cancelled context) is an error and tainted.
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if tainted, err := s.ReadPAConversationTaint(cctx, alice, conv.ID); !tainted || !errors.Is(err, convo.ErrUnreadable) {
			t.Fatalf("cancelled read: tainted=%v err=%v", tainted, err)
		}
	})
}

// TestS2I10_ReadErrorOnBrokenSchema: a taint read against a table that
// cannot be read is an error and tainted, never clean.
func TestS2I10_ReadErrorOnBrokenSchema(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	openConv(t, s, 555, "x-1", t0)
	if _, err := s.DB.Exec(`ALTER TABLE pa_conversations RENAME TO pa_conversations_gone`); err != nil {
		t.Fatal(err)
	}
	if tainted, err := s.ReadPAConversationTaint(ctx, 555, "x-1"); !tainted || !errors.Is(err, convo.ErrStoreFault) {
		t.Fatalf("broken table: tainted=%v err=%v, want tainted and a store fault", tainted, err)
	}
}

// TestS2I7_MigrationTaintsExistingRows: rows that existed before the column
// migrate tainted; a conversation created after it starts clean.
func TestS2I7_MigrationTaintsExistingRows(t *testing.T) {
	run := func(t *testing.T, conn *sql.DB) {
		ctx := context.Background()
		if err := Migrate(ctx, conn); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(`INSERT INTO pa_conversations(id, principal, created_at_ms, expires_at_ms, closed_at_ms)
			VALUES('pre', 555, $1, $2, 0)`, t0.UnixMilli(), t0.Add(time.Hour).UnixMilli()); err != nil {
			t.Fatal(err)
		}
		// The schema as it was before #1321.
		if _, err := conn.Exec(`ALTER TABLE pa_conversations DROP COLUMN tainted`); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(ctx, conn); err != nil {
			t.Fatal(err)
		}
		s := NewStore(conn, nil)
		if !mustTaint(t, s, 555, "pre") {
			t.Fatal("a conversation from before the column migrated clean")
		}
		c := openConv(t, s, 556, "post", t0)
		if mustTaint(t, s, 556, c.ID) {
			t.Fatal("a conversation created after the migration starts tainted")
		}
	}
	t.Run("sqlite", func(t *testing.T) { run(t, newTestStore(t).DB) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		run(t, emptyPostgresSchema(t, dsn))
	})
}

// taintAssign finds an assignment to the tainted column in SQL text.
var taintAssign = regexp.MustCompile(`(?i)\btainted\s*=\s*([^\s,)]+)`)

// TestS2I8_NoStatementLowersTaint is a static check over every non-test Go
// file of the module: the only value any SQL string literal assigns to
// tainted is 1. A reset must come from a new row (/new, TTL, /forget,
// purge), never from an UPDATE that a model, a tool or a forwarded
// "reset taint" could ever reach. The only literal that writes a 0 is the
// INSERT that creates a conversation.
func TestS2I8_NoStatementLowersTaint(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	inserts, scanned := 0, 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".worktrees", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				text = lit.Value
			}
			for _, m := range taintAssign.FindAllStringSubmatch(text, -1) {
				if m[1] != "1" {
					t.Errorf("%s: SQL assigns tainted = %s; only 1 is allowed:\n%s", path, m[1], text)
				}
			}
			low := strings.ToLower(text)
			if strings.Contains(low, "tainted") && strings.Contains(low, "insert into pa_conversations") {
				inserts++
			}
			if strings.Contains(low, "tainted") && strings.Contains(low, "on conflict") &&
				strings.Contains(low, "do update") && strings.Contains(low, "pa_conversations") {
				t.Errorf("%s: an upsert of pa_conversations could rewrite tainted:\n%s", path, text)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 50 || inserts != 1 {
		t.Fatalf("scanned %d files, %d conversation inserts naming tainted: the check did not see the module", scanned, inserts)
	}
}
