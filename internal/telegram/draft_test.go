package telegram

import (
	"errors"
	"testing"
)

func TestDecideDraft(t *testing.T) {
	cases := []struct {
		name           string
		existing, text string
		overwrite      bool
		wantConflict   bool
		wantUnits      int
		wantReplaced   bool
		wantUnchanged  bool
		wantCleared    bool
	}{
		{name: "empty chat, new draft", existing: "", text: "hi"},
		{name: "same text is a no-op", existing: "hi", text: "hi", wantUnchanged: true},
		{name: "user draft is kept", existing: "Bob, about Friday", text: "hi", wantConflict: true, wantUnits: 17},
		{name: "user draft kept on clear too", existing: "x", text: "", wantConflict: true, wantUnits: 1},
		{name: "emoji counted in UTF-16", existing: "\U0001F600", text: "hi", wantConflict: true, wantUnits: 2},
		{name: "overwrite replaces", existing: "old", text: "new", overwrite: true, wantReplaced: true},
		{name: "overwrite clears", existing: "old", text: "", overwrite: true, wantReplaced: true, wantCleared: true},
		{name: "clear an empty chat", existing: "", text: "", wantUnchanged: true, wantCleared: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decideDraft(c.existing, c.text, c.overwrite)
			if c.wantConflict {
				var dc *DraftConflict
				if !errors.As(err, &dc) || !errors.Is(err, ErrDraftExists) {
					t.Fatalf("err = %v, want a DraftConflict", err)
				}
				if dc.ExistingUnits != c.wantUnits {
					t.Errorf("ExistingUnits = %d, want %d", dc.ExistingUnits, c.wantUnits)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.ReplacedExisting != c.wantReplaced || got.Unchanged != c.wantUnchanged || got.Cleared != c.wantCleared {
				t.Errorf("got %+v, want replaced=%v unchanged=%v cleared=%v", got, c.wantReplaced, c.wantUnchanged, c.wantCleared)
			}
		})
	}
}
