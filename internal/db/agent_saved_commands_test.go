package db

import (
	"context"
	"testing"
)

func TestSavedCommandCursorPersistsAndNeverRegresses(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	userID, err := s.EnsureUser(ctx, "saved-cursor-test", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	if got, found, getErr := s.GetSavedCommandCursor(ctx, userID); getErr != nil || found || got != 0 {
		t.Fatalf("initial cursor = %d, found=%v, err=%v", got, found, getErr)
	}
	if err := s.AdvanceSavedCommandCursor(ctx, userID, 42); err != nil {
		t.Fatalf("create cursor: %v", err)
	}
	if err := s.AdvanceSavedCommandCursor(ctx, userID, 17); err != nil {
		t.Fatalf("regressing update: %v", err)
	}
	if got, found, err := s.GetSavedCommandCursor(ctx, userID); err != nil || !found || got != 42 {
		t.Fatalf("persisted cursor = %d, found=%v, err=%v", got, found, err)
	}
}
