package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
)

func TestAssistantDefinitions(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { checkAssistantDefinitions(t, newTestStoreCrypted(t)) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		checkAssistantDefinitions(t, newPostgresTestStore(t, dsn))
	})
}

// checkAssistantDefinitions: the snapshot and the profile UPDATE commit
// together (an install whose UPDATE fails, here for want of a profile row,
// leaves no snapshot behind), and the registry notice is queued once per
// stale check whether the check time was read back or kept in memory.
func checkAssistantDefinitions(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	// Postgres keeps state between runs: a fresh digest and account each time.
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + hex.EncodeToString(b[:])
	uid, err := s.EnsureUserByTelegramID(ctx, 500100202, "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM agent_profiles WHERE user_id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	def := AssistantDefinition{
		Digest: digest, Name: "other-assistant", Version: "0.2.0",
		Document: []byte(`{"kind":"TelegramAssistant"}`), Lifecycle: AssistantLifecyclePublished,
	}
	name, version := def.Name, def.Version
	listening := true
	u := AgentProfileUpdate{AssistantName: &name, AssistantVersion: &version, AssistantDigest: &digest,
		BumpInstallRevision: true, ListenerEnabled: &listening}

	if err := s.InstallAgentAssistant(ctx, uid, def, u); !errors.Is(err, ErrAgentProfileNotFound) {
		t.Fatalf("install without a profile: err = %v", err)
	}
	if _, err := s.GetAssistantDefinition(ctx, digest); !errors.Is(err, ErrAssistantDefinitionNotFound) {
		t.Fatalf("snapshot after a failed install: err = %v, want not found", err)
	}

	if err := s.EnsureAgentProfile(ctx, uid); err != nil {
		t.Fatal(err)
	}
	before, err := s.GetAgentProfile(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.InstallAgentAssistant(ctx, uid, def, u); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.GetAssistantDefinition(ctx, digest)
	if err != nil || string(got.Document) != string(def.Document) || got.Lifecycle != AssistantLifecyclePublished {
		t.Fatalf("snapshot = %+v, err=%v", got, err)
	}
	if p, err := s.GetAgentProfile(ctx, uid); err != nil || p.InstallRevision != before.InstallRevision+2 {
		t.Fatalf("revision = %+v, err=%v, want %d", p, err, before.InstallRevision+2)
	}
	other := "sha256:cd"
	bad := u
	bad.AssistantDigest = &other
	if err := s.InstallAgentAssistant(ctx, uid, def, bad); err == nil {
		t.Fatal("accepted an install pinning another digest than the stored one")
	}

	pinned, err := s.ListPinnedAssistantDefinitions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range pinned {
		found = found || d.Digest == digest
	}
	if !found {
		t.Fatal("pinned definition not listed")
	}

	checked := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.SetAssistantDefinitionLifecycle(ctx, digest, AssistantLifecycleDeprecated, checked); err != nil {
		t.Fatal(err)
	}
	read, err := s.GetAssistantDefinition(ctx, digest)
	if err != nil || read.Lifecycle != AssistantLifecycleDeprecated {
		t.Fatalf("lifecycle = %+v, err=%v", read, err)
	}
	for i, at := range []time.Time{checked, read.LifecycleCheckedAt, checked} {
		sent, err := s.NotifyAssistantRegistryUnreachable(ctx, uid, digest, at, "notice")
		if err != nil || sent != (i == 0) {
			t.Fatalf("notice %d: sent=%v err=%v", i, sent, err)
		}
	}
	if sent, err := s.NotifyAssistantRegistryUnreachable(ctx, uid, digest, checked.Add(time.Minute), "notice"); err != nil || !sent {
		t.Fatalf("notice after a newer check: sent=%v err=%v", sent, err)
	}
}
