package db

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestAssistantForks(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { checkAssistantForks(t, newTestStoreCrypted(t)) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		checkAssistantForks(t, newPostgresTestStore(t, dsn))
	})
}

func randomDigest(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + hex.EncodeToString(b[:])
}

// forkRow is a fork version of a fixed base for uid.
func forkRow(t *testing.T, uid int64, name, version, baseDigest string) AssistantFork {
	return AssistantFork{
		UserID: uid, Name: name, Version: version, Digest: randomDigest(t),
		BaseName: "hr-recruiter", BaseVersion: "0.1.0", BaseDigest: baseDigest,
		Document: []byte(`{"spec":{"instructions":{"text":"PRIVATE-FORK-TEXT ` + name + `@` + version + `"}}}`),
	}
}

// checkAssistantForks: per-account encryption and isolation, the version
// fence, both quotas, the notice in the same transaction, delete of a
// pinned version, install against a deleted fork, and the account purge.
func checkAssistantForks(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	// Postgres keeps state between runs: fresh accounts each time.
	var tag [4]byte
	if _, err := rand.Read(tag[:]); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(tag[:])
	alice, err := s.EnsureUserByTelegramID(ctx, 500100101, "alice"+suffix, "Alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.EnsureUserByTelegramID(ctx, 500100202, "bob"+suffix, "Bob")
	if err != nil {
		t.Fatal(err)
	}
	for _, uid := range []int64{alice, bob} {
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM assistant_forks WHERE user_id = $1`, uid); err != nil {
			t.Fatal(err)
		}
	}
	base := randomDigest(t)
	name := "hr-recruiter~abcdefgh23~careful"

	// Owner scope: deterministic per account, different across accounts.
	ma, err := s.ForkOwnerMAC(alice)
	if err != nil {
		t.Fatal(err)
	}
	ma2, _ := s.ForkOwnerMAC(alice)
	mb, _ := s.ForkOwnerMAC(bob)
	if !bytes.Equal(ma, ma2) || bytes.Equal(ma, mb) {
		t.Fatal("owner MAC is not per account")
	}

	v1 := forkRow(t, alice, name, "0.1.0", base)
	if err := s.InsertAssistantFork(ctx, v1, "", "Fork saved."); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Sealed at rest with Alice's key.
	var sealed []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT document_encrypted FROM assistant_forks WHERE user_id = $1 AND digest = $2`,
		alice, v1.Digest).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("PRIVATE-FORK-TEXT")) {
		t.Fatal("fork document stored in plaintext")
	}
	if _, err := s.Crypt.OpenForUser(sealed, bob); err == nil {
		t.Fatal("Bob's key opens Alice's fork")
	}
	got, err := s.GetAssistantForkByDigest(ctx, alice, v1.Digest)
	if err != nil || !bytes.Equal(got.Document, v1.Document) || got.Promotion != ForkPromotionObserve {
		t.Fatalf("read back = %+v, %v", got, err)
	}
	// The notice was queued with the write.
	var notices int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1`, alice).Scan(&notices); err != nil || notices != 1 {
		t.Fatalf("notices = %d, %v", notices, err)
	}

	// Another account reads nothing of it, by digest or by name.
	if _, err := s.GetAssistantForkByDigest(ctx, bob, v1.Digest); !errors.Is(err, ErrAssistantForkNotFound) {
		t.Fatalf("Bob by digest: %v", err)
	}
	if _, err := s.GetLatestAssistantFork(ctx, bob, name); !errors.Is(err, ErrAssistantForkNotFound) {
		t.Fatalf("Bob by name: %v", err)
	}
	if l, err := s.ListAssistantForks(ctx, bob); err != nil || len(l) != 0 {
		t.Fatalf("Bob's list = %v, %v", l, err)
	}

	// The version fence: a new fork whose name is taken, an edit of a
	// version that is not the latest.
	if err := s.InsertAssistantFork(ctx, forkRow(t, alice, name, "0.1.1", base), "", ""); !errors.Is(err, ErrForkConflict) {
		t.Fatalf("taken name: %v", err)
	}
	v2 := forkRow(t, alice, name, "0.1.1", base)
	if err := s.InsertAssistantFork(ctx, v2, "0.1.0", ""); err != nil {
		t.Fatalf("edit: %v", err)
	}
	if err := s.InsertAssistantFork(ctx, forkRow(t, alice, name, "0.2.0", base), "0.1.0", ""); !errors.Is(err, ErrForkConflict) {
		t.Fatalf("stale edit: %v", err)
	}
	if latest, err := s.GetLatestAssistantFork(ctx, alice, name); err != nil || latest.Version != "0.1.1" {
		t.Fatalf("latest = %+v, %v", latest, err)
	}

	// Versions quota: 50 per fork; the 51st changes nothing.
	prev := "0.1.1"
	for i := 2; i < MaxVersionsPerFork; i++ {
		v := fmt.Sprintf("0.1.%d", i)
		if err := s.InsertAssistantFork(ctx, forkRow(t, alice, name, v, base), prev, ""); err != nil {
			t.Fatalf("version %s: %v", v, err)
		}
		prev = v
	}
	if err := s.InsertAssistantFork(ctx, forkRow(t, alice, name, "0.2.0", base), prev, "Fork saved."); !errors.Is(err, ErrForkLimit) {
		t.Fatalf("version %d: %v, want fork_limit", MaxVersionsPerFork+1, err)
	}
	// Forks quota: 10 per account; the 11th changes nothing.
	for i := 1; i < MaxForksPerAccount; i++ {
		if err := s.InsertAssistantFork(ctx, forkRow(t, alice, fmt.Sprintf("hr-recruiter~abcdefgh23~f%d", i), "0.1.0", base), "", ""); err != nil {
			t.Fatalf("fork %d: %v", i, err)
		}
	}
	if err := s.InsertAssistantFork(ctx, forkRow(t, alice, "hr-recruiter~abcdefgh23~one-too-many", "0.1.0", base), "", "Fork saved."); !errors.Is(err, ErrForkLimit) {
		t.Fatalf("fork %d: %v, want fork_limit", MaxForksPerAccount+1, err)
	}
	var rows int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM assistant_forks WHERE user_id = $1`, alice).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if want := MaxVersionsPerFork + MaxForksPerAccount - 1; rows != want {
		t.Fatalf("fork rows = %d, want %d: a refused write stored something", rows, want)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1`, alice).Scan(&notices); err != nil || notices != 1 {
		t.Fatalf("notices = %d, %v: a refused write queued a notice", notices, err)
	}
	// Bob's quota is his own.
	if err := s.InsertAssistantFork(ctx, forkRow(t, bob, "hr-recruiter~zyxwvuts23~mine", "0.1.0", base), "", ""); err != nil {
		t.Fatalf("Bob's first fork: %v", err)
	}

	// Install pins v2; deleting it, or the whole fork, is refused.
	if err := s.EnsureAgentProfile(ctx, alice); err != nil {
		t.Fatal(err)
	}
	digest, version := v2.Digest, v2.Version
	u := AgentProfileUpdate{AssistantName: &name, AssistantVersion: &version, AssistantDigest: &digest, BumpInstallRevision: true}
	if err := s.InstallAgentFork(ctx, alice, v2.Digest, nil, u); err != nil {
		t.Fatalf("install: %v", err)
	}
	// Bob cannot install Alice's fork version.
	if err := s.EnsureAgentProfile(ctx, bob); err != nil {
		t.Fatal(err)
	}
	if err := s.InstallAgentFork(ctx, bob, v2.Digest, nil, u); !errors.Is(err, ErrAssistantForkNotFound) {
		t.Fatalf("Bob installs Alice's fork: %v", err)
	}
	if _, err := s.DeleteAssistantFork(ctx, alice, name, "0.1.1"); !errors.Is(err, ErrForkInUse) {
		t.Fatalf("delete pinned version: %v", err)
	}
	if _, err := s.DeleteAssistantFork(ctx, alice, name, ""); !errors.Is(err, ErrForkInUse) {
		t.Fatalf("delete pinned fork: %v", err)
	}
	if n, err := s.DeleteAssistantFork(ctx, alice, name, "0.1.0"); err != nil || n != 1 {
		t.Fatalf("delete unpinned version: %d, %v", n, err)
	}
	if _, err := s.DeleteAssistantFork(ctx, bob, name, ""); !errors.Is(err, ErrAssistantForkNotFound) {
		t.Fatalf("Bob deletes Alice's fork: %v", err)
	}
	// A deleted version cannot be installed.
	if err := s.InstallAgentFork(ctx, alice, v1.Digest, nil, AgentProfileUpdate{AssistantDigest: &v1.Digest}); !errors.Is(err, ErrAssistantForkNotFound) {
		t.Fatalf("install deleted version: %v", err)
	}

	// The purge removes every fork of the account, and only of it.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := purgeAgentData(ctx, tx, alice); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM assistant_forks WHERE user_id = $1`, alice).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("Alice's forks after purge = %d, %v", rows, err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM assistant_forks WHERE user_id = $1`, bob).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("Bob's forks after Alice's purge = %d, %v", rows, err)
	}
}

// A fork's base is refreshed and its owner notified like a pinned catalog
// version: the fork's lifecycle is its base's.
func TestAssistantForks_BaseFollowsThePin(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 500100101, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureAgentProfile(ctx, uid); err != nil {
		t.Fatal(err)
	}
	base := AssistantDefinition{Digest: randomDigest(t), Name: "hr-recruiter", Version: "0.1.0",
		Document: []byte(`{}`), Lifecycle: AssistantLifecyclePublished}
	f := forkRow(t, uid, "hr-recruiter~abcdefgh23~careful", "0.1.0", base.Digest)
	if err := s.InsertAssistantFork(ctx, f, "", ""); err != nil {
		t.Fatal(err)
	}
	listening := true
	u := AgentProfileUpdate{AssistantName: &f.Name, AssistantVersion: &f.Version, AssistantDigest: &f.Digest, ListenerEnabled: &listening}
	wrong := base
	wrong.Digest = randomDigest(t)
	if err := s.InstallAgentFork(ctx, uid, f.Digest, &wrong, u); err == nil {
		t.Fatal("installed with a snapshot that is not the fork's base")
	}
	if err := s.InstallAgentFork(ctx, uid, f.Digest, &base, u); err != nil {
		t.Fatal(err)
	}
	pinned, err := s.ListPinnedAssistantDefinitions(ctx)
	if err != nil || len(pinned) != 1 || pinned[0].Digest != base.Digest {
		t.Fatalf("pinned = %+v, %v; want the fork's base", pinned, err)
	}
	users, err := s.ListListeningUsersPinnedTo(ctx, base.Digest)
	if err != nil || len(users) != 1 || users[0] != uid {
		t.Fatalf("listening users = %v, %v", users, err)
	}
	sent, err := s.NotifyAssistantRegistryUnreachable(ctx, uid, base.Digest, base.FetchedAt, "unreachable")
	if err != nil || !sent {
		t.Fatalf("notice for the fork's base: sent=%v err=%v", sent, err)
	}
}
