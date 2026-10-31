package assistantinstall

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func newTestService(t *testing.T) (*Service, int64) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	crypt, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(conn, crypt)
	uid, err := store.EnsureUserByTelegramID(ctx, 500100101, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	return New(store, catalog, nil), uid
}

func hrInstall(t *testing.T, mode string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "assistants.mctl.ai/v1alpha1", "kind": "AssistantInstall",
		"spec": map[string]any{
			"assistant": map[string]any{"name": "hr-recruiter", "version": "0.1.0"},
			"mode":      mode,
			"values":    map[string]any{"name": "Alice", "role": "Engineer"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Without a caller's revision, the commit is still a compare-and-set on
// the revision it read: an install that lands between that read and the
// UPDATE is a conflict, not overwritten on the strength of gates decided
// from the state it replaced.
func TestCommit_WithoutExpectedRevisionStillComparesAndSets(t *testing.T) {
	svc, uid := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Apply(ctx, uid, hrInstall(t, "observe"), CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	before, err := svc.Store.GetAgentAssistant(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	raced := false
	svc.beforeWrite = func() {
		if raced {
			return
		}
		raced = true
		// A concurrent install moves the revision after Commit read it.
		if err := svc.Store.UpdateAgentProfileFields(ctx, uid, db.AgentProfileUpdate{BumpInstallRevision: true}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = svc.Apply(ctx, uid, hrInstall(t, "guarded"), CommitOptions{})
	var ie *Error
	if !errors.As(err, &ie) || ie.Kind != KindRevisionConflict || ie.CurrentRevision != before.InstallRevision+1 {
		t.Fatalf("err = %v, want a revision conflict at %d", err, before.InstallRevision+1)
	}
	p, err := svc.Store.GetAgentProfile(ctx, uid)
	if err != nil || p.Mode != "observe" {
		t.Fatalf("profile after the race = %+v, err %v; the losing install was written", p, err)
	}
}

func TestCurrent_FreshAccountReportsTheStartingRevision(t *testing.T) {
	svc, uid := newTestService(t)
	ctx := context.Background()
	cur, err := svc.Current(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	rev := cur.InstallRevision
	if cur.Installed || rev != 1 {
		t.Fatalf("current = %+v", cur)
	}
	if _, err := svc.Apply(ctx, uid, hrInstall(t, "observe"), CommitOptions{ExpectedRevision: &rev, SelfService: true}); err != nil {
		t.Fatalf("install at the reported revision: %v", err)
	}
}
