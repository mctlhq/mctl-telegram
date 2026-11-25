package db

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDashboardTemplates_RoundTripAndQuota(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "alice", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := s.SaveDashboardTemplate(ctx, uid, "custom_pulse", "Мой", `{"id":"custom_pulse"}`, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDashboardTemplate(ctx, uid, "custom_pulse", "Мой 2", `{"id":"custom_pulse","v":2}`, 2); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDashboardTemplate(ctx, uid, "custom_pulse")
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "Мой 2" || !strings.Contains(got.Body, `"v":2`) || got.UpdatedAt.IsZero() {
		t.Fatalf("got = %+v", got)
	}
	if err := s.SaveDashboardTemplate(ctx, uid, "second", "Второй", `{}`, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDashboardTemplate(ctx, uid, "third", "Третий", `{}`, 2); !errors.Is(err, ErrDashboardTemplateQuota) {
		t.Fatalf("third save err = %v, want quota", err)
	}
	list, err := s.ListDashboardTemplates(ctx, uid)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	other, err := s.EnsureUser(ctx, "bob", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDashboardTemplate(ctx, other, "custom_pulse"); !errors.Is(err, ErrDashboardTemplateNotFound) {
		t.Fatalf("other user get = %v", err)
	}
	if err := s.DeleteDashboardTemplate(ctx, uid, "custom_pulse"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDashboardTemplate(ctx, uid, "custom_pulse"); !errors.Is(err, ErrDashboardTemplateNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}
