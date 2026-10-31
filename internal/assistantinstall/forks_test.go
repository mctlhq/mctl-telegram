package assistantinstall

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/assistant"
)

// An install prepared for one account's fork cannot be committed to
// another account, whichever surface splits Prepare from Commit.
func TestCommit_ForkOnlyForItsOwner(t *testing.T) {
	svc, alice := newTestService(t)
	svc.ForksEnabled = true
	ctx := context.Background()
	text := "Careful.\n"
	w, err := svc.CreateFork(ctx, alice, "hr-recruiter", "0.1.0", "careful", assistant.ForkOverrides{Instructions: &text})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "assistants.mctl.ai/v1alpha1", "kind": "AssistantInstall",
		"spec": map[string]any{
			"assistant": map[string]any{"name": w.Name, "version": w.Version},
			"mode":      "observe",
			"values":    map[string]any{"name": "Alice", "role": "Engineer"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.prepare(ctx, alice, raw)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := svc.Store.EnsureUserByTelegramID(ctx, 500100202, "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	var ie *Error
	if _, err := svc.Commit(ctx, bob, p, CommitOptions{SelfService: true}); !errors.As(err, &ie) || ie.Kind != KindNotFound {
		t.Fatalf("commit of Alice's fork for Bob = %v, want not found", err)
	}
	if res, err := svc.Commit(ctx, alice, p, CommitOptions{SelfService: true}); err != nil || res.Name != w.Name {
		t.Fatalf("commit for Alice = %+v, %v", res, err)
	}
}
