package assistantinstall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func runtimeInstall(t *testing.T, runtime, consent string) json.RawMessage {
	t.Helper()
	spec := map[string]any{
		"assistant": map[string]any{"name": "hr-recruiter", "version": "0.1.0"},
		"mode":      "observe",
		"values":    map[string]any{"name": "Alice", "role": "Engineer"},
	}
	if runtime != "" {
		spec["runtime"] = runtime
	}
	if consent != "" {
		spec["consent"] = consent
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "assistants.mctl.ai/v1alpha1", "kind": "AssistantInstall", "spec": spec,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func wantKind(t *testing.T, err error, kind Kind) {
	t.Helper()
	var ie *Error
	if !errors.As(err, &ie) || ie.Kind != kind {
		t.Fatalf("err = %v, want kind %d", err, kind)
	}
}

func TestDecideRuntime(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	on := ManagedRuntime{Enabled: true, MaxAccounts: 1}
	off := ManagedRuntime{}
	cur := db.ManagedConsentCurrent

	if _, e := off.DecideRuntime("own", "managed", "", now); e == nil || e.Kind != KindManagedDisabled {
		t.Fatalf("flag off without consent: %v", e)
	}
	if _, e := off.DecideRuntime("own", "managed", cur, now); e == nil || e.Kind != KindManagedDisabled {
		t.Fatalf("flag off with consent: %v", e)
	}
	if _, e := on.DecideRuntime("own", "managed", "", now); e == nil || e.Kind != KindManagedConsentRequired {
		t.Fatalf("no consent: %v", e)
	}
	if _, e := on.DecideRuntime("", "managed", "managed-data-flow/v0", now); e == nil || e.Kind != KindManagedConsentRequired {
		t.Fatalf("old consent: %v", e)
	}
	ch, e := on.DecideRuntime("own", "managed", cur, now)
	if e != nil || !ch.Changed || ch.Quota == nil || *ch.Quota != 1 || *ch.ConsentVersion != cur || !ch.ConsentAt.Equal(now) {
		t.Fatalf("switch = %+v, %v", ch, e)
	}
	ch, e = off.DecideRuntime("managed", "own", "", now)
	if e != nil || !ch.Changed || *ch.Runtime != "own" || ch.ConsentVersion != nil {
		t.Fatalf("managed -> own = %+v, %v", ch, e)
	}
	ch, e = off.DecideRuntime("managed", "managed", "", now)
	if e != nil || ch.Quota != nil || ch.ConsentVersion != nil || ch.Changed {
		t.Fatalf("managed keep = %+v, %v", ch, e)
	}
	ch, e = on.DecideRuntime("managed", "managed", cur, now)
	if e != nil || !ch.Consented || ch.Changed || ch.Quota != nil {
		t.Fatalf("re-consent = %+v, %v", ch, e)
	}
	if ch, e = on.DecideRuntime("managed", "", "", now); e != nil || ch.Runtime != nil {
		t.Fatalf("unchanged = %+v, %v", ch, e)
	}
}

func TestCommit_SwitchToManagedNeedsConsentAndStoresNoConsent(t *testing.T) {
	svc, uid := newTestService(t)
	ctx := context.Background()
	svc.Managed = ManagedRuntime{Enabled: true, MaxAccounts: 5}
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return at }

	_, err := svc.Apply(ctx, uid, runtimeInstall(t, "managed", ""), CommitOptions{})
	wantKind(t, err, KindManagedConsentRequired)
	p, err := svc.Store.GetAgentProfile(ctx, uid)
	if err != nil || p.Runtime != "own" || p.ManagedConsentVersion != "" {
		t.Fatalf("profile after refusal = %+v, %v", p, err)
	}

	res, err := svc.Apply(ctx, uid, runtimeInstall(t, "managed", db.ManagedConsentCurrent), CommitOptions{})
	if err != nil {
		t.Fatalf("consented switch: %v", err)
	}
	if res.Profile.Runtime != "managed" || res.Profile.ManagedConsentVersion != db.ManagedConsentCurrent ||
		!res.Profile.ManagedConsentAt.Equal(at) || res.Profile.NeedsManagedReconsent() {
		t.Fatalf("profile = %+v", res.Profile)
	}
	a, err := svc.Store.GetAgentAssistant(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(a.Install), "consent") {
		t.Fatalf("stored install carries consent: %s", a.Install)
	}

	// managed -> own needs nothing, even with the flag off.
	svc.Managed = ManagedRuntime{}
	rev := a.InstallRevision
	if _, err := svc.Patch(ctx, uid, json.RawMessage(`{"runtime":"own"}`), rev); err != nil {
		t.Fatalf("managed -> own: %v", err)
	}
	p, _ = svc.Store.GetAgentProfile(ctx, uid)
	if p.Runtime != "own" || p.ManagedConsentVersion != db.ManagedConsentCurrent {
		t.Fatalf("profile after switching back = %+v", p)
	}

	// A later patch cannot inherit the earlier consent.
	svc.Managed = ManagedRuntime{Enabled: true, MaxAccounts: 5}
	_, err = svc.Patch(ctx, uid, json.RawMessage(`{"runtime":"managed"}`), rev+1)
	wantKind(t, err, KindManagedConsentRequired)
	if _, err := svc.PatchWithConsent(ctx, uid, json.RawMessage(`{"runtime":"managed"}`), rev+1, db.ManagedConsentCurrent); err != nil {
		t.Fatalf("patch with consent: %v", err)
	}
	// Flag off, own -> managed is disabled even with consent.
	svc.Managed = ManagedRuntime{}
	if _, err := svc.PatchWithConsent(ctx, uid, json.RawMessage(`{"runtime":"own"}`), rev+2, ""); err != nil {
		t.Fatal(err)
	}
	_, err = svc.PatchWithConsent(ctx, uid, json.RawMessage(`{"runtime":"managed"}`), rev+3, db.ManagedConsentCurrent)
	wantKind(t, err, KindManagedDisabled)
}

func TestCommit_ManagedQuota(t *testing.T) {
	svc, alice := newTestService(t)
	ctx := context.Background()
	bob, err := svc.Store.EnsureUserByTelegramID(ctx, 500100102, "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	svc.Managed = ManagedRuntime{Enabled: true, MaxAccounts: 1}
	consent := db.ManagedConsentCurrent
	if _, err := svc.Apply(ctx, bob, runtimeInstall(t, "managed", consent), CommitOptions{}); err != nil {
		t.Fatalf("bob: %v", err)
	}
	_, err = svc.Apply(ctx, alice, runtimeInstall(t, "managed", consent), CommitOptions{})
	wantKind(t, err, KindManagedQuota)
	// Bob reinstalling does not count himself.
	if _, err := svc.Apply(ctx, bob, runtimeInstall(t, "managed", ""), CommitOptions{}); err != nil {
		t.Fatalf("bob reinstall: %v", err)
	}
	if _, err := svc.Apply(ctx, bob, runtimeInstall(t, "own", ""), CommitOptions{}); err != nil {
		t.Fatalf("bob back to own: %v", err)
	}
	if _, err := svc.Apply(ctx, alice, runtimeInstall(t, "managed", consent), CommitOptions{}); err != nil {
		t.Fatalf("alice after bob left: %v", err)
	}
	if n, err := svc.Store.CountManagedAccounts(ctx); err != nil || n != 1 {
		t.Fatalf("managed accounts = %d, %v", n, err)
	}
}

func TestCommit_ManagedQuotaConcurrent(t *testing.T) {
	svc, alice := newTestService(t)
	ctx := context.Background()
	bob, err := svc.Store.EnsureUserByTelegramID(ctx, 500100102, "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	svc.Managed = ManagedRuntime{Enabled: true, MaxAccounts: 1}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, uid := range []int64{alice, bob} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = svc.Apply(ctx, uid, runtimeInstall(t, "managed", db.ManagedConsentCurrent), CommitOptions{})
		}()
	}
	wg.Wait()
	ok := 0
	for _, e := range errs {
		if e == nil {
			ok++
		}
	}
	if n, _ := svc.Store.CountManagedAccounts(ctx); n != 1 || ok != 1 {
		t.Fatalf("managed = %d, successes = %d, errs = %v", n, ok, errs)
	}
}

func TestReconsentRequired(t *testing.T) {
	p := db.AgentProfile{Runtime: "managed", ManagedConsentVersion: "managed-data-flow/v0"}
	if !p.NeedsManagedReconsent() || !SettingsOf(&p).ManagedReconsentRequired {
		t.Fatal("old consent must need re-consent")
	}
	p.ManagedConsentVersion = db.ManagedConsentCurrent
	if p.NeedsManagedReconsent() {
		t.Fatal("current consent must not")
	}
	if (db.AgentProfile{}).NeedsManagedReconsent() {
		t.Fatal("own never does")
	}
}

func TestConsentTextIsInTheADR(t *testing.T) {
	b, err := os.ReadFile("../../docs/adr/0008-managed-runtime.md")
	if err != nil {
		t.Fatal(err)
	}
	norm := strings.Join(strings.Fields(strings.ReplaceAll(string(b), "*", "")), " ")
	if !strings.Contains(norm, db.ManagedConsentText) {
		t.Fatal("ADR 0008 does not contain db.ManagedConsentText verbatim")
	}
}
