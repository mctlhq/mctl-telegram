package policy

import (
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestAudienceExcluded(t *testing.T) {
	installed := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	before, after := installed.Add(-time.Hour), installed.Add(time.Hour)
	cases := []struct {
		name     string
		excludes string
		at       time.Time // install time; zero means never installed
		contact  string
		created  time.Time
		want     bool
	}{
		{"nothing excluded", "", installed, "", after, false},
		{"contact, contacts out", "contacts", installed, db.PeerContactYes, after, true},
		{"non-contact, contacts out", "contacts", installed, db.PeerContactNo, after, false},
		{"non-contact, non_contacts out", "non_contacts", installed, db.PeerContactNo, after, true},
		{"unknown contact, non_contacts out", "non_contacts", installed, "", before, true},
		{"chat before install, new out", "new_chats", installed, db.PeerContactNo, before, false},
		{"chat after install, new out", "new_chats", installed, db.PeerContactNo, after, true},
		{"contact after install counts as existing", "new_chats", installed, db.PeerContactYes, after, false},
		{"chat before install, existing out", "existing_chats", installed, db.PeerContactNo, before, true},
		{"chat after install, existing out", "existing_chats", installed, db.PeerContactNo, after, false},
		{"unknown contact after install, existing out", "existing_chats", installed, "", after, true},
		{"unknown contact before install, existing out", "existing_chats", installed, "", before, true},
		{"no install time", "new_chats", time.Time{}, db.PeerContactNo, before, true},
		{"unknown class", "vips", installed, db.PeerContactNo, before, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := db.AgentProfile{AudienceExcludes: tc.excludes, AssistantInstalledAt: tc.at}
			c := db.Conversation{PeerContact: tc.contact, CreatedAt: tc.created}
			reason, got := AudienceExcluded(p, c)
			if got != tc.want {
				t.Fatalf("excluded = %v (%q), want %v", got, reason, tc.want)
			}
			if got && reason == "" {
				t.Fatal("excluded without a reason")
			}
		})
	}
}

func TestValidAudienceExcludes(t *testing.T) {
	for csv, installed := range map[string]bool{"": false, "contacts": false, "non_contacts,new_chats": true} {
		if err := ValidAudienceExcludes(csv, installed); err != nil {
			t.Errorf("%q (installed=%v): %v", csv, installed, err)
		}
	}
	for csv, installed := range map[string]bool{
		"vips":                     true,
		"contacts,non_contacts":    true,
		"new_chats,existing_chats": true,
		"new_chats":                false,
	} {
		if err := ValidAudienceExcludes(csv, installed); err == nil {
			t.Errorf("%q (installed=%v) accepted", csv, installed)
		}
	}
}
