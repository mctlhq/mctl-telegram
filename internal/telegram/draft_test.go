package telegram

import (
	"errors"
	"testing"

	"github.com/gotd/td/tg"
)

func TestDecideDraft(t *testing.T) {
	cases := []struct {
		name           string
		existing, text string
		other          bool
		overwrite      bool
		wantConflict   bool
		wantUnits      int
		wantAttachment bool
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
		{name: "media-only draft is kept", other: true, text: "hi", wantConflict: true, wantUnits: 0, wantAttachment: true},
		{name: "media-only draft kept on clear", other: true, text: "", wantConflict: true, wantAttachment: true},
		{name: "same text plus a reply is not unchanged", existing: "hi", other: true, text: "hi", wantConflict: true, wantUnits: 2, wantAttachment: true},
		{name: "overwrite replaces a media draft", other: true, text: "hi", overwrite: true, wantReplaced: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decideDraft(existingDraft{Text: c.existing, Other: c.other}, c.text, c.overwrite)
			if c.wantConflict {
				var dc *DraftConflict
				if !errors.As(err, &dc) || !errors.Is(err, ErrDraftExists) {
					t.Fatalf("err = %v, want a DraftConflict", err)
				}
				if dc.HasAttachment != c.wantAttachment {
					t.Errorf("HasAttachment = %v, want %v", dc.HasAttachment, c.wantAttachment)
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

// The chat's dialog is found wherever it sits in the answer: an archived
// chat or one in a folder can come back with a folder entry first.
func TestDraftFromDialogs(t *testing.T) {
	folder := &tg.DialogFolder{Folder: tg.Folder{ID: 1, Title: "Archive"}}
	withText := &tg.Dialog{Draft: &tg.DraftMessage{Message: "Bob, about Friday"}}
	media := &tg.DraftMessage{}
	media.SetMedia(&tg.InputMediaEmpty{})
	withMedia := &tg.Dialog{Draft: media}
	reply := &tg.DraftMessage{}
	reply.SetReplyTo(&tg.InputReplyToMessage{ReplyToMsgID: 5})
	withReply := &tg.Dialog{Draft: reply}

	cases := []struct {
		name    string
		in      []tg.DialogClass
		want    existingDraft
		wantErr bool
	}{
		{name: "no dialog row", in: nil},
		{name: "no draft", in: []tg.DialogClass{&tg.Dialog{}}},
		{name: "empty draft", in: []tg.DialogClass{&tg.Dialog{Draft: &tg.DraftMessageEmpty{}}}},
		{name: "text draft", in: []tg.DialogClass{withText}, want: existingDraft{Text: "Bob, about Friday"}},
		{name: "folder first", in: []tg.DialogClass{folder, withText}, want: existingDraft{Text: "Bob, about Friday"}},
		{name: "media only", in: []tg.DialogClass{withMedia}, want: existingDraft{Other: true}},
		{name: "reply only", in: []tg.DialogClass{withReply}, want: existingDraft{Other: true}},
		{name: "only a folder", in: []tg.DialogClass{folder}, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := draftFromDialogs(c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}
